const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.warn("WARNING: JWT_SECRET is not configured.");
}

/* =========================================================
   MYSQL CONNECTION POOL
   IMPORTANT:
   Do NOT use localhost on Vercel.
   Set these in Vercel Environment Variables.
========================================================= */

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0
});

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));

/*
   Public folder:
   school-system/
   ├── api/
   │   └── index.js
   └── public/
*/
app.use(express.static(path.join(__dirname, "..", "public")));

/* =========================================================
   HELPER FUNCTIONS
========================================================= */

function sendError(res, error, message = "Server error") {
    console.error(message, error);

    return res.status(500).json({
        success: false,
        message
    });
}

function calculateGrade(score) {
    score = Number(score);

    if (score >= 75) return "A";
    if (score >= 65) return "B";
    if (score >= 55) return "C";
    if (score >= 45) return "D";
    if (score >= 40) return "E";
    return "F";
}

/* =========================================================
   AUTHENTICATION MIDDLEWARE
========================================================= */

function auth(req, res, next) {
    try {
        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            });
        }

        const token = header.split(" ")[1];

        if (!JWT_SECRET) {
            return res.status(500).json({
                success: false,
                message: "JWT_SECRET is not configured"
            });
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Invalid or expired token"
        });
    }
}

/* =========================================================
   ROLE MIDDLEWARE
========================================================= */

function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Admin access required"
        });
    }

    next();
}

function teacherOnly(req, res, next) {
    if (
        !req.user ||
        (req.user.role !== "teacher" && req.user.role !== "admin")
    ) {
        return res.status(403).json({
            success: false,
            message: "Teacher access required"
        });
    }

    next();
}

function studentOnly(req, res, next) {
    if (!req.user || req.user.role !== "student") {
        return res.status(403).json({
            success: false,
            message: "Student access required"
        });
    }

    next();
}

function parentOnly(req, res, next) {
    if (!req.user || req.user.role !== "parent") {
        return res.status(403).json({
            success: false,
            message: "Parent access required"
        });
    }

    next();
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
    res.sendFile(
        path.join(__dirname, "..", "public", "login.html")
    );
});

/* =========================================================
   HEALTH / DATABASE TEST
========================================================= */

app.get("/db-test", async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT 1 AS connected");

        res.json({
            success: true,
            message: "Database connection successful",
            database: rows
        });
    } catch (error) {
        sendError(res, error, "Database connection failed");
    }
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/register", async (req, res) => {
    let connection;

    try {
        const {
            username,
            password,
            role = "student",
            name,
            class: studentClass,
            age,
            subject
        } = req.body;

        if (!username || !password || !name) {
            return res.status(400).json({
                success: false,
                message: "Username, password and name are required"
            });
        }

        const allowedRoles = [
            "admin",
            "teacher",
            "student",
            "parent"
        ];

        if (!allowedRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                message: "Invalid role"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        connection = await pool.getConnection();

        await connection.beginTransaction();

        const [existing] = await connection.query(
            "SELECT id FROM users WHERE username = ? LIMIT 1",
            [username]
        );

        if (existing.length > 0) {
            await connection.rollback();

            return res.status(409).json({
                success: false,
                message: "Username already exists"
            });
        }

        const [userResult] = await connection.query(
            `
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
            `,
            [username, hashedPassword, role]
        );

        const userId = userResult.insertId;

        /* Automatically link student */

        if (role === "student") {
            await connection.query(
                `
                INSERT INTO students
                (user_id, name, class, age)
                VALUES (?, ?, ?, ?)
                `,
                [
                    userId,
                    name,
                    studentClass || null,
                    age || null
                ]
            );
        }

        /* Automatically link teacher */

        if (role === "teacher") {
            await connection.query(
                `
                INSERT INTO teachers
                (user_id, name, subject, class)
                VALUES (?, ?, ?, ?)
                `,
                [
                    userId,
                    name,
                    subject || null,
                    studentClass || null
                ]
            );
        }

        await connection.commit();

        res.status(201).json({
            success: true,
            message: "User created successfully",
            userId,
            role
        });

    } catch (error) {

        if (connection) {
            try {
                await connection.rollback();
            } catch {}
        }

        sendError(res, error, "Registration failed");

    } finally {

        if (connection) {
            connection.release();
        }
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: "Username and password are required"
            });
        }

        const [rows] = await pool.query(
            `
            SELECT id, username, password, role
            FROM users
            WHERE username = ?
            LIMIT 1
            `,
            [username]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password"
            });
        }

        const user = rows[0];

        const validPassword = await bcrypt.compare(
            password,
            user.password
        );

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password"
            });
        }

        if (!JWT_SECRET) {
            return res.status(500).json({
                success: false,
                message: "JWT_SECRET is not configured"
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.json({
            success: true,
            message: "Login successful",
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });

    } catch (error) {
        sendError(res, error, "Login failed");
    }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/me", auth, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT id, username, role
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        res.json({
            success: true,
            user: rows[0]
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   ADMIN - USERS
========================================================= */

app.get("/admin/users", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                id,
                username,
                role,
                created_at
            FROM users
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            users: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

app.delete("/admin/users/:id", auth, adminOnly, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!id) {
            return res.status(400).json({
                success: false,
                message: "Invalid user ID"
            });
        }

        if (id === Number(req.user.id)) {
            return res.status(400).json({
                success: false,
                message: "You cannot delete your own account"
            });
        }

        await pool.query(
            "DELETE FROM users WHERE id = ?",
            [id]
        );

        res.json({
            success: true,
            message: "User deleted successfully"
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   ADMIN - STUDENTS
========================================================= */

app.get("/admin/students", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                s.id,
                s.user_id,
                s.name,
                s.class,
                s.age,
                u.username
            FROM students s
            LEFT JOIN users u
                ON u.id = s.user_id
            ORDER BY s.id DESC
            `
        );

        res.json({
            success: true,
            students: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

app.post("/admin/students", auth, adminOnly, async (req, res) => {
    try {
        const {
            user_id,
            name,
            class: studentClass,
            age
        } = req.body;

        if (!user_id || !name) {
            return res.status(400).json({
                success: false,
                message: "user_id and name are required"
            });
        }

        const [result] = await pool.query(
            `
            INSERT INTO students
            (user_id, name, class, age)
            VALUES (?, ?, ?, ?)
            `,
            [
                user_id,
                name,
                studentClass || null,
                age || null
            ]
        );

        res.status(201).json({
            success: true,
            message: "Student profile created",
            student_id: result.insertId
        });

    } catch (error) {
        sendError(res, error, "Could not create student");
    }
});

/* =========================================================
   STUDENT PROFILE
========================================================= */

app.get("/student/profile", auth, studentOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                s.id,
                s.user_id,
                s.name,
                s.class,
                s.age,
                u.username
            FROM students s
            LEFT JOIN users u
                ON u.id = s.user_id
            WHERE s.user_id = ?
            LIMIT 1
            `,
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Student profile not found"
            });
        }

        res.json({
            success: true,
            student: rows[0]
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   ADMIN - TEACHERS
========================================================= */

app.get("/admin/teachers", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                t.id,
                t.user_id,
                t.name,
                t.subject,
                t.class,
                u.username
            FROM teachers t
            LEFT JOIN users u
                ON u.id = t.user_id
            ORDER BY t.id DESC
            `
        );

        res.json({
            success: true,
            teachers: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   TEACHER PROFILE
========================================================= */

app.get("/teacher/profile", auth, teacherOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                t.id,
                t.user_id,
                t.name,
                t.subject,
                t.class,
                u.username
            FROM teachers t
            LEFT JOIN users u
                ON u.id = t.user_id
            WHERE t.user_id = ?
            LIMIT 1
            `,
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Teacher profile not found"
            });
        }

        res.json({
            success: true,
            teacher: rows[0]
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   ADMIN - SUBJECTS
========================================================= */

app.get("/admin/subjects", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT *
            FROM subjects
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            subjects: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

app.post("/admin/subjects", auth, adminOnly, async (req, res) => {
    try {
        const {
            name,
            code
        } = req.body;

        if (!name) {
            return res.status(400).json({
                success: false,
                message: "Subject name is required"
            });
        }

        const [result] = await pool.query(
            `
            INSERT INTO subjects
            (name, code)
            VALUES (?, ?)
            `,
            [
                name,
                code || null
            ]
        );

        res.status(201).json({
            success: true,
            message: "Subject created",
            subject_id: result.insertId
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   STUDENT - SUBJECTS
========================================================= */

app.get("/student/subjects", auth, studentOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT *
            FROM subjects
            ORDER BY name ASC
            `
        );

        res.json({
            success: true,
            subjects: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   RESULTS - ADMIN
========================================================= */

app.get("/admin/results", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                r.*,
                s.name AS student_name,
                t.name AS teacher_name
            FROM results r
            LEFT JOIN students s
                ON s.id = r.student_id
            LEFT JOIN teachers t
                ON t.id = r.teacher_id
            ORDER BY r.id DESC
            `
        );

        res.json({
            success: true,
            results: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

app.post("/admin/results", auth, adminOnly, async (req, res) => {
    try {
        const {
            student_id,
            subject,
            score,
            term,
            session,
            teacher_id
        } = req.body;

        if (!student_id || !subject || score === undefined) {
            return res.status(400).json({
                success: false,
                message: "student_id, subject and score are required"
            });
        }

        const grade = calculateGrade(score);

        const [result] = await pool.query(
            `
            INSERT INTO results
            (
                student_id,
                subject,
                score,
                grade,
                term,
                session,
                teacher_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
            [
                student_id,
                subject,
                score,
                grade,
                term || null,
                session || null,
                teacher_id || null
            ]
        );

        res.status(201).json({
            success: true,
            message: "Result added",
            result_id: result.insertId,
            grade
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   STUDENT RESULTS
========================================================= */

app.get("/student/results", auth, studentOnly, async (req, res) => {
    try {
        const [student] = await pool.query(
            `
            SELECT id
            FROM students
            WHERE user_id = ?
            LIMIT 1
            `,
            [req.user.id]
        );

        if (student.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Student profile not found"
            });
        }

        const studentId = student[0].id;

        const [results] = await pool.query(
            `
            SELECT *
            FROM results
            WHERE student_id = ?
            ORDER BY id DESC
            `,
            [studentId]
        );

        res.json({
            success: true,
            results
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   EXAMS - ADMIN
========================================================= */

app.get("/admin/exams", auth, adminOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT *
            FROM exams
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            exams: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

app.post("/admin/exams", auth, adminOnly, async (req, res) => {
    try {
        const {
            title,
            subject,
            duration,
            total_questions,
            status
        } = req.body;

        if (!title || !subject) {
            return res.status(400).json({
                success: false,
                message: "Title and subject are required"
            });
        }

        const [result] = await pool.query(
            `
            INSERT INTO exams
            (
                title,
                subject,
                duration,
                total_questions,
                status
            )
            VALUES (?, ?, ?, ?, ?)
            `,
            [
                title,
                subject,
                duration || 30,
                total_questions || 10,
                status || "inactive"
            ]
        );

        res.status(201).json({
            success: true,
            message: "Exam created",
            exam_id: result.insertId
        });

    } catch (error) {
        sendError(res, error, "Could not create exam");
    }
});

/* =========================================================
   CHANGE EXAM STATUS
========================================================= */

app.put(
    "/admin/exams/:id/status",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const id = Number(req.params.id);
            const { status } = req.body;

            const allowedStatuses = [
                "active",
                "inactive",
                "closed"
            ];

            if (!allowedStatuses.includes(status)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid exam status"
                });
            }

            await pool.query(
                `
                UPDATE exams
                SET status = ?
                WHERE id = ?
                `,
                [status, id]
            );

            res.json({
                success: true,
                message: "Exam status updated"
            });

        } catch (error) {
            sendError(res, error);
        }
    }
);

/* =========================================================
   STUDENT - ACTIVE EXAMS
========================================================= */

app.get("/student/exams", auth, studentOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                id,
                title,
                subject,
                duration,
                total_questions,
                status
            FROM exams
            WHERE status = 'active'
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            exams: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* Alias */
app.get("/student/active-exams", auth, studentOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                id,
                title,
                subject,
                duration,
                total_questions,
                status
            FROM exams
            WHERE status = 'active'
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            exams: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   QUESTIONS - ADMIN
========================================================= */

app.get("/admin/questions", auth, adminOnly, async (req, res) => {
    try {
        const { exam_id } = req.query;

        let sql = `
            SELECT *
            FROM questions
        `;

        const params = [];

        if (exam_id) {
            sql += `
                WHERE exam_id = ?
            `;

            params.push(exam_id);
        }

        sql += `
            ORDER BY id DESC
        `;

        const [rows] = await pool.query(sql, params);

        res.json({
            success: true,
            questions: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   ADD QUESTION
========================================================= */

app.post("/admin/questions", auth, adminOnly, async (req, res) => {
    try {
        const {
            exam_id,
            question,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        } = req.body;

        if (
            !exam_id ||
            !question ||
            !option_a ||
            !option_b ||
            !option_c ||
            !option_d ||
            !correct_answer
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "exam_id, question, all options and correct_answer are required"
            });
        }

        const validAnswers = [
            "A",
            "B",
            "C",
            "D",
            "a",
            "b",
            "c",
            "d"
        ];

        if (!validAnswers.includes(correct_answer)) {
            return res.status(400).json({
                success: false,
                message: "correct_answer must be A, B, C or D"
            });
        }

        const answer = correct_answer.toUpperCase();

        const [result] = await pool.query(
            `
            INSERT INTO questions
            (
                exam_id,
                question,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            `,
            [
                exam_id,
                question,
                option_a,
                option_b,
                option_c,
                option_d,
                answer
            ]
        );

        res.status(201).json({
            success: true,
            message: "Question added successfully",
            question_id: result.insertId
        });

    } catch (error) {
        sendError(res, error, "Could not add question");
    }
});

/* =========================================================
   UPDATE QUESTION
========================================================= */

app.put("/admin/questions/:id", auth, adminOnly, async (req, res) => {
    try {
        const id = Number(req.params.id);

        const {
            exam_id,
            question,
            option_a,
            option_b,
            option_c,
            option_d,
            correct_answer
        } = req.body;

        if (!id || !question) {
            return res.status(400).json({
                success: false,
                message: "Question ID and question are required"
            });
        }

        await pool.query(
            `
            UPDATE questions
            SET
                exam_id = ?,
                question = ?,
                option_a = ?,
                option_b = ?,
                option_c = ?,
                option_d = ?,
                correct_answer = ?
            WHERE id = ?
            `,
            [
                exam_id,
                question,
                option_a,
                option_b,
                option_c,
                option_d,
                String(correct_answer).toUpperCase(),
                id
            ]
        );

        res.json({
            success: true,
            message: "Question updated successfully"
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   DELETE QUESTION
========================================================= */

app.delete(
    "/admin/questions/:id",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!id) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid question ID"
                });
            }

            await pool.query(
                "DELETE FROM questions WHERE id = ?",
                [id]
            );

            res.json({
                success: true,
                message: "Question deleted"
            });

        } catch (error) {
            sendError(res, error);
        }
    }
);

/* =========================================================
   STUDENT - START CBT
========================================================= */

app.post(
    "/student/exams/:examId/start",
    auth,
    studentOnly,
    async (req, res) => {
        let connection;

        try {
            const examId = Number(req.params.examId);

            if (!examId) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid exam ID"
                });
            }

            connection = await pool.getConnection();

            /* Find student */

            const [students] = await connection.query(
                `
                SELECT id, name
                FROM students
                WHERE user_id = ?
                LIMIT 1
                `,
                [req.user.id]
            );

            if (students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Student profile not found"
                });
            }

            const studentId = students[0].id;

            /* Check exam */

            const [exams] = await connection.query(
                `
                SELECT *
                FROM exams
                WHERE id = ?
                LIMIT 1
                `,
                [examId]
            );

            if (exams.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Exam not found"
                });
            }

            const exam = exams[0];

            if (exam.status !== "active") {
                return res.status(403).json({
                    success: false,
                    message: "This exam is not active"
                });
            }

            /*
              Check whether the student already has an attempt.
              This prevents taking the same CBT repeatedly.
            */

            const [attempts] = await connection.query(
                `
                SELECT *
                FROM cbt_attempts
                WHERE student_id = ?
                AND exam_id = ?
                LIMIT 1
                `,
                [studentId, examId]
            );

            if (attempts.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: "You have already started this CBT",
                    attempt: attempts[0]
                });
            }

            /* Get questions */

            const [questions] = await connection.query(
                `
                SELECT
                    id,
                    exam_id,
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d
                FROM questions
                WHERE exam_id = ?
                ORDER BY RAND()
                LIMIT ?
                `,
                [
                    examId,
                    Number(exam.total_questions || 10)
                ]
            );

            if (questions.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: "This exam has no questions"
                });
            }

            /* Create attempt */

            const [attemptResult] = await connection.query(
                `
                INSERT INTO cbt_attempts
                (
                    exam_id,
                    student_id,
                    completed
                )
                VALUES (?, ?, 0)
                `,
                [
                    examId,
                    studentId
                ]
            );

            res.json({
                success: true,
                message: "CBT started",
                attempt_id: attemptResult.insertId,
                exam: {
                    id: exam.id,
                    title: exam.title,
                    subject: exam.subject,
                    duration: exam.duration,
                    total_questions: questions.length
                },
                questions
            });

        } catch (error) {
            sendError(res, error, "Could not start CBT");

        } finally {

            if (connection) {
                connection.release();
            }
        }
    }
);

/* =========================================================
   SUBMIT CBT
========================================================= */

app.post(
    "/student/exams/:examId/submit",
    auth,
    studentOnly,
    async (req, res) => {
        let connection;

        try {
            const examId = Number(req.params.examId);
            const { answers = {} } = req.body;

            connection = await pool.getConnection();

            /* Find student */

            const [students] = await connection.query(
                `
                SELECT id, name
                FROM students
                WHERE user_id = ?
                LIMIT 1
                `,
                [req.user.id]
            );

            if (students.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Student profile not found"
                });
            }

            const studentId = students[0].id;

            /* Find attempt */

            const [attempts] = await connection.query(
                `
                SELECT *
                FROM cbt_attempts
                WHERE student_id = ?
                AND exam_id = ?
                ORDER BY id DESC
                LIMIT 1
                `,
                [
                    studentId,
                    examId
                ]
            );

            if (attempts.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "CBT attempt not found"
                });
            }

            const attempt = attempts[0];

            if (Number(attempt.completed) === 1) {
                return res.status(409).json({
                    success: false,
                    message: "This CBT has already been submitted"
                });
            }

            /* Get correct answers */

            const [questions] = await connection.query(
                `
                SELECT
                    id,
                    correct_answer
                FROM questions
                WHERE exam_id = ?
                `,
                [examId]
            );

            let score = 0;

            for (const question of questions) {

                const studentAnswer =
                    answers[question.id] ||
                    answers[String(question.id)];

                if (
                    studentAnswer &&
                    String(studentAnswer).toUpperCase() ===
                    String(question.correct_answer).toUpperCase()
                ) {
                    score++;
                }
            }

            const total = questions.length;

            const percentage =
                total > 0
                    ? Math.round((score / total) * 100)
                    : 0;

            const grade = calculateGrade(percentage);

            await connection.query(
                `
                UPDATE cbt_attempts
                SET
                    score = ?,
                    completed = 1
                WHERE id = ?
                `,
                [
                    percentage,
                    attempt.id
                ]
            );

            /* Also save result */

            const [examRows] = await connection.query(
                `
                SELECT subject
                FROM exams
                WHERE id = ?
                LIMIT 1
                `,
                [examId]
            );

            if (examRows.length > 0) {

                await connection.query(
                    `
                    INSERT INTO results
                    (
                        student_id,
                        subject,
                        score,
                        grade
                    )
                    VALUES (?, ?, ?, ?)
                    `,
                    [
                        studentId,
                        examRows[0].subject,
                        percentage,
                        grade
                    ]
                );
            }

            res.json({
                success: true,
                message: "CBT submitted successfully",
                result: {
                    correct: score,
                    total,
                    score: percentage,
                    grade
                }
            });

        } catch (error) {
            sendError(res, error, "Could not submit CBT");

        } finally {

            if (connection) {
                connection.release();
            }
        }
    }
);

/* =========================================================
   TEACHER - STUDENTS
========================================================= */

app.get("/teacher/students", auth, teacherOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                s.id,
                s.user_id,
                s.name,
                s.class,
                s.age,
                u.username
            FROM students s
            LEFT JOIN users u
                ON u.id = s.user_id
            ORDER BY s.name ASC
            `
        );

        res.json({
            success: true,
            students: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   TEACHER - RESULTS
========================================================= */

app.get("/teacher/results", auth, teacherOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT
                r.*,
                s.name AS student_name
            FROM results r
            LEFT JOIN students s
                ON s.id = r.student_id
            ORDER BY r.id DESC
            `
        );

        res.json({
            success: true,
            results: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   TEACHER - EXAMS
   READ ONLY
========================================================= */

app.get("/teacher/exams", auth, teacherOnly, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `
            SELECT *
            FROM exams
            ORDER BY id DESC
            `
        );

        res.json({
            success: true,
            exams: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   TEACHER - QUESTIONS
   READ ONLY
========================================================= */

app.get("/teacher/questions", auth, teacherOnly, async (req, res) => {
    try {
        const { exam_id } = req.query;

        let sql = `
            SELECT *
            FROM questions
        `;

        const params = [];

        if (exam_id) {
            sql += " WHERE exam_id = ?";
            params.push(exam_id);
        }

        sql += " ORDER BY id DESC";

        const [rows] = await pool.query(sql, params);

        res.json({
            success: true,
            questions: rows
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   TEACHER - STUDENT PERFORMANCE
========================================================= */

app.get(
    "/teacher/student/:studentId/performance",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const studentId = Number(req.params.studentId);

            const [student] = await pool.query(
                `
                SELECT
                    id,
                    name,
                    class,
                    age
                FROM students
                WHERE id = ?
                LIMIT 1
                `,
                [studentId]
            );

            if (student.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Student not found"
                });
            }

            const [results] = await pool.query(
                `
                SELECT *
                FROM results
                WHERE student_id = ?
                ORDER BY id DESC
                `,
                [studentId]
            );

            res.json({
                success: true,
                student: student[0],
                results
            });

        } catch (error) {
            sendError(res, error);
        }
    }
);

/* =========================================================
   PARENT - STUDENTS
========================================================= */

app.get("/parent/profile", auth, parentOnly, async (req, res) => {
    try {
        /*
          This assumes a parents table with:
          id, user_id, name
        */

        const [rows] = await pool.query(
            `
            SELECT
                p.id,
                p.user_id,
                p.name,
                u.username
            FROM parents p
            LEFT JOIN users u
                ON u.id = p.user_id
            WHERE p.user_id = ?
            LIMIT 1
            `,
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Parent profile not found"
            });
        }

        res.json({
            success: true,
            parent: rows[0]
        });

    } catch (error) {
        sendError(res, error);
    }
});

/* =========================================================
   PARENT - STUDENT PERFORMANCE
========================================================= */

app.get(
    "/parent/student/:studentId/results",
    auth,
    parentOnly,
    async (req, res) => {
        try {
            const studentId = Number(req.params.studentId);

            const [rows] = await pool.query(
                `
                SELECT
                    r.*,
                    s.name AS student_name
                FROM results r
                JOIN students s
                    ON s.id = r.student_id
                WHERE r.student_id = ?
                ORDER BY r.id DESC
                `,
                [studentId]
            );

            res.json({
                success: true,
                results: rows
            });

        } catch (error) {
            sendError(res, error);
        }
    }
);

/* =========================================================
   LOGOUT
   JWT IS STATELESS
========================================================= */

app.post("/logout", auth, (req, res) => {
    res.json({
        success: true,
        message:
            "Logged out successfully. Remove the token from the browser."
    });
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Route not found",
        path: req.originalUrl
    });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);

    res.status(500).json({
        success: false,
        message: "Internal server error"
    });
});

/* =========================================================
   VERCEL EXPORT
   DO NOT USE app.listen()
========================================================= */

module.exports = app;