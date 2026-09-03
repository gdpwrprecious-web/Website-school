const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const JWT_SECRET = "school_backend_secret_2026";

const pool = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "school_db",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
    try {
        const header = req.headers.authorization;

        if (!header || !header.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const token = header.split(" ")[1];

        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({
            message: "Admin access required"
        });
    }

    next();
}

function teacherOnly(req, res, next) {
    if (!req.user || req.user.role !== "teacher") {
        return res.status(403).json({
            message: "Teacher access required"
        });
    }

    next();
}

/* =========================
   BASIC ROUTES
========================= */

app.get("/", (req, res) => {
    res.send(`
        <h1>School Management System</h1>
        <p>Backend is running.</p>
        <p><a href="/login.html">Login</a></p>
    `);
});

app.get("/db-test", async (req, res) => {
    try {
        const [rows] = await pool.query("SELECT 1 AS test");

        res.json({
            success: true,
            message: "Database connected",
            data: rows
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Database connection failed",
            error: error.message
        });
    }
});

/* =========================
   REGISTER
   CREATE USER
   AUTO LINK PROFILE
========================= */

app.post("/register", async (req, res) => {
    const connection = await pool.getConnection();

    try {
        const {
            username,
            password,
            role,
            name,
            class: studentClass,
            age,
            subject,
            teacherClass
        } = req.body;

        if (!username || !password || !role) {
            return res.status(400).json({
                message: "Username, password and role are required"
            });
        }

        const allowedRoles = ["admin", "teacher", "student", "parent"];

        if (!allowedRoles.includes(role)) {
            return res.status(400).json({
                message: "Invalid role"
            });
        }

        if (password.length < 4) {
            return res.status(400).json({
                message: "Password must be at least 4 characters"
            });
        }

        const [existing] = await connection.query(
            "SELECT id FROM users WHERE username = ? LIMIT 1",
            [username.trim()]
        );

        if (existing.length) {
            return res.status(409).json({
                message: "Username already exists"
            });
        }

        await connection.beginTransaction();

        const hashedPassword = await bcrypt.hash(password, 10);

        const [userResult] = await connection.query(
            `
            INSERT INTO users
            (username, password, role)
            VALUES (?, ?, ?)
            `,
            [
                username.trim(),
                hashedPassword,
                role
            ]
        );

        const userId = userResult.insertId;

        /* =========================
           AUTOMATIC STUDENT LINK
        ========================= */

        if (role === "student") {
            if (!name || !studentClass || !age) {
                await connection.rollback();

                return res.status(400).json({
                    message:
                        "Student requires name, class and age"
                });
            }

            await connection.query(
                `
                INSERT INTO students
                (name, class, age, user_id)
                VALUES (?, ?, ?, ?)
                `,
                [
                    name.trim(),
                    studentClass.trim(),
                    Number(age),
                    userId
                ]
            );
        }

        /* =========================
           AUTOMATIC TEACHER LINK
        ========================= */

        if (role === "teacher") {
            if (!name) {
                await connection.rollback();

                return res.status(400).json({
                    message: "Teacher requires a name"
                });
            }

            await connection.query(
                `
                INSERT INTO teachers
                (user_id, name, subject, class)
                VALUES (?, ?, ?, ?)
                `,
                [
                    userId,
                    name.trim(),
                    subject || "",
                    teacherClass || ""
                ]
            );
        }

        await connection.commit();

        res.status(201).json({
            success: true,
            message:
                role === "student"
                    ? "Student account created and automatically linked"
                    : role === "teacher"
                    ? "Teacher account created and automatically linked"
                    : "User created successfully",
            userId
        });

    } catch (error) {
        await connection.rollback();

        console.error("REGISTER ERROR:", error);

        res.status(500).json({
            message: "Could not create user",
            error: error.message
        });
    } finally {
        connection.release();
    }
});

/* =========================
   LOGIN
========================= */

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
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
            [username.trim()]
        );

        if (!rows.length) {
            return res.status(401).json({
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
                message: "Invalid username or password"
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
        console.error(error);

        res.status(500).json({
            message: "Login failed",
            error: error.message
        });
    }
});

/* =========================
   ADMIN USERS
========================= */

app.get(
    "/admin/users",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    id,
                    username,
                    role,
                    created_at
                FROM users
                ORDER BY id DESC
            `);

            res.json({
                users: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load users"
            });
        }
    }
);

app.delete(
    "/admin/users/:id",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!id) {
                return res.status(400).json({
                    message: "Invalid user ID"
                });
            }

            if (id === req.user.id) {
                return res.status(400).json({
                    message: "You cannot delete your own account"
                });
            }

            await pool.query(
                "DELETE FROM users WHERE id = ?",
                [id]
            );

            res.json({
                success: true,
                message: "User deleted"
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to delete user",
                error: error.message
            });
        }
    }
);

/* =========================
   STUDENTS
========================= */

app.get(
    "/admin/students",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    s.id,
                    s.name,
                    s.class,
                    s.age,
                    s.user_id,
                    u.username
                FROM students s
                LEFT JOIN users u
                    ON s.user_id = u.id
                ORDER BY s.id DESC
            `);

            res.json({
                students: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load students"
            });
        }
    }
);

app.post(
    "/admin/students",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const {
                name,
                class: studentClass,
                age
            } = req.body;

            if (!name || !studentClass || !age) {
                return res.status(400).json({
                    message: "Name, class and age are required"
                });
            }

            const [result] = await pool.query(
                `
                INSERT INTO students
                (name, class, age)
                VALUES (?, ?, ?)
                `,
                [
                    name,
                    studentClass,
                    Number(age)
                ]
            );

            res.status(201).json({
                success: true,
                message: "Student profile created",
                id: result.insertId
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to create student"
            });
        }
    }
);

/* =========================
   STUDENT PROFILE
========================= */

app.get(
    "/student/profile",
    auth,
    async (req, res) => {
        try {
            const [rows] = await pool.query(
                `
                SELECT
                    s.id,
                    s.name,
                    s.class,
                    s.age,
                    s.user_id,
                    u.username
                FROM students s
                LEFT JOIN users u
                    ON s.user_id = u.id
                WHERE s.user_id = ?
                LIMIT 1
                `,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({
                    message: "Student profile not found"
                });
            }

            res.json({
                student: rows[0]
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load profile"
            });
        }
    }
);

/* =========================
   TEACHERS
========================= */

app.get(
    "/admin/teachers",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    t.id,
                    t.name,
                    t.subject,
                    t.class,
                    t.user_id,
                    u.username
                FROM teachers t
                LEFT JOIN users u
                    ON t.user_id = u.id
                ORDER BY t.id DESC
            `);

            res.json({
                teachers: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load teachers"
            });
        }
    }
);

/* =========================
   TEACHER PROFILE
========================= */

app.get(
    "/teacher/profile",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(
                `
                SELECT
                    t.id,
                    t.name,
                    t.subject,
                    t.class,
                    u.username
                FROM teachers t
                LEFT JOIN users u
                    ON t.user_id = u.id
                WHERE t.user_id = ?
                LIMIT 1
                `,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({
                    message: "Teacher profile not found"
                });
            }

            res.json({
                teacher: rows[0]
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load teacher profile"
            });
        }
    }
);

/* =========================
   SUBJECTS
========================= */

app.get(
    "/admin/subjects",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT *
                FROM subjects
                ORDER BY id DESC
            `);

            res.json({
                subjects: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load subjects"
            });
        }
    }
);

app.post(
    "/admin/subjects",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const { name, code } = req.body;

            if (!name) {
                return res.status(400).json({
                    message: "Subject name required"
                });
            }

            const [result] = await pool.query(
                `
                INSERT INTO subjects
                (name, code)
                VALUES (?, ?)
                `,
                [name, code || ""]
            );

            res.status(201).json({
                success: true,
                message: "Subject created",
                id: result.insertId
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to create subject"
            });
        }
    }
);

app.get(
    "/student/subjects",
    auth,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT *
                FROM subjects
                ORDER BY name ASC
            `);

            res.json({
                subjects: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load subjects"
            });
        }
    }
);

/* =========================
   RESULTS
========================= */

function calculateGrade(score) {
    score = Number(score);

    if (score >= 75) return "A";
    if (score >= 65) return "B";
    if (score >= 55) return "C";
    if (score >= 45) return "D";
    if (score >= 40) return "E";
    return "F";
}

app.get(
    "/admin/results",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    r.*,
                    s.name AS student_name
                FROM results r
                LEFT JOIN students s
                    ON r.student_id = s.id
                ORDER BY r.id DESC
            `);

            res.json({
                results: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load results"
            });
        }
    }
);

app.post(
    "/admin/results",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const {
                student_id,
                subject,
                score,
                term,
                session
            } = req.body;

            if (!student_id || !subject || score === undefined) {
                return res.status(400).json({
                    message:
                        "Student, subject and score are required"
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
                    session
                )
                VALUES (?, ?, ?, ?, ?, ?)
                `,
                [
                    student_id,
                    subject,
                    Number(score),
                    grade,
                    term || "",
                    session || ""
                ]
            );

            res.status(201).json({
                success: true,
                message: "Result added",
                id: result.insertId
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to add result"
            });
        }
    }
);

app.get(
    "/student/results",
    auth,
    async (req, res) => {
        try {
            const [rows] = await pool.query(
                `
                SELECT
                    r.*,
                    s.name AS student_name
                FROM results r
                INNER JOIN students s
                    ON r.student_id = s.id
                WHERE s.user_id = ?
                ORDER BY r.created_at DESC
                `,
                [req.user.id]
            );

            res.json({
                results: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load results"
            });
        }
    }
);

/* =========================
   EXAMS
========================= */

app.get(
    "/admin/exams",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT *
                FROM exams
                ORDER BY id DESC
            `);

            res.json({
                exams: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load exams"
            });
        }
    }
);

app.post(
    "/admin/exams",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const {
                title,
                subject,
                duration,
                total_questions,
                status
            } = req.body;

            if (
                !title ||
                !subject ||
                !duration ||
                !total_questions
            ) {
                return res.status(400).json({
                    message:
                        "Title, subject, duration and question count are required"
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
                    Number(duration),
                    Number(total_questions),
                    status || "draft"
                ]
            );

            res.status(201).json({
                success: true,
                message: "Exam created",
                id: result.insertId
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to create exam"
            });
        }
    }
);

app.put(
    "/admin/exams/:id/status",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const { status } = req.body;

            await pool.query(
                `
                UPDATE exams
                SET status = ?
                WHERE id = ?
                `,
                [status, req.params.id]
            );

            res.json({
                success: true,
                message: "Exam status updated"
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to update exam"
            });
        }
    }
);

app.get(
    "/student/exams",
    auth,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    id,
                    title,
                    subject,
                    duration,
                    total_questions,
                    status,
                    created_at
                FROM exams
                WHERE status = 'active'
                ORDER BY created_at DESC
            `);

            res.json({
                exams: rows
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to load exams"
            });
        }
    }
);

/* =========================
   QUESTIONS
========================= */

app.get(
    "/admin/questions/:examId",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(
                `
                SELECT
                    id,
                    exam_id,
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    correct_answer,
                    created_at
                FROM questions
                WHERE exam_id = ?
                ORDER BY id ASC
                `,
                [req.params.examId]
            );

            res.json({
                questions: rows
            });

        } catch (error) {
            console.error("QUESTION LOAD ERROR:", error);

            res.status(500).json({
                message: "Failed to load questions",
                error: error.message
            });
        }
    }
);

app.post(
    "/admin/questions",
    auth,
    adminOnly,
    async (req, res) => {
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
                    message:
                        "Exam, question, all four options and correct answer are required"
                });
            }

            const answer =
                String(correct_answer)
                    .trim()
                    .toUpperCase();

            if (!["A", "B", "C", "D"].includes(answer)) {
                return res.status(400).json({
                    message:
                        "Correct answer must be A, B, C or D"
                });
            }

            const [exam] = await pool.query(
                `
                SELECT id
                FROM exams
                WHERE id = ?
                LIMIT 1
                `,
                [exam_id]
            );

            if (!exam.length) {
                return res.status(404).json({
                    message: "Exam not found"
                });
            }

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
                    Number(exam_id),
                    question.trim(),
                    option_a.trim(),
                    option_b.trim(),
                    option_c.trim(),
                    option_d.trim(),
                    answer
                ]
            );

            res.status(201).json({
                success: true,
                message: "Question added successfully",
                id: result.insertId
            });

        } catch (error) {
            console.error("ADD QUESTION ERROR:", error);

            res.status(500).json({
                message: "Failed to add question",
                error: error.message
            });
        }
    }
);

app.put(
    "/admin/questions/:id",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            const {
                question,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer
            } = req.body;

            const answer =
                String(correct_answer)
                    .trim()
                    .toUpperCase();

            if (!["A", "B", "C", "D"].includes(answer)) {
                return res.status(400).json({
                    message: "Correct answer must be A, B, C or D"
                });
            }

            await pool.query(
                `
                UPDATE questions
                SET
                    question = ?,
                    option_a = ?,
                    option_b = ?,
                    option_c = ?,
                    option_d = ?,
                    correct_answer = ?
                WHERE id = ?
                `,
                [
                    question,
                    option_a,
                    option_b,
                    option_c,
                    option_d,
                    answer,
                    req.params.id
                ]
            );

            res.json({
                success: true,
                message: "Question updated"
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to update question"
            });
        }
    }
);

app.delete(
    "/admin/questions/:id",
    auth,
    adminOnly,
    async (req, res) => {
        try {
            await pool.query(
                "DELETE FROM questions WHERE id = ?",
                [req.params.id]
            );

            res.json({
                success: true,
                message: "Question deleted"
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to delete question"
            });
        }
    }
);

/* =========================
   STUDENT CBT
========================= */

async function getStudentId(userId) {
    const [rows] = await pool.query(
        `
        SELECT id
        FROM students
        WHERE user_id = ?
        LIMIT 1
        `,
        [userId]
    );

    return rows.length ? rows[0].id : null;
}

app.post(
    "/student/exams/:id/start",
    auth,
    async (req, res) => {
        try {
            const studentId =
                await getStudentId(req.user.id);

            if (!studentId) {
                return res.status(404).json({
                    message: "Student profile not linked"
                });
            }

            const examId = Number(req.params.id);

            const [exam] = await pool.query(
                `
                SELECT *
                FROM exams
                WHERE id = ?
                AND status = 'active'
                LIMIT 1
                `,
                [examId]
            );

            if (!exam.length) {
                return res.status(404).json({
                    message: "Active exam not found"
                });
            }

            const [existing] = await pool.query(
                `
                SELECT *
                FROM cbt_attempts
                WHERE exam_id = ?
                AND student_id = ?
                LIMIT 1
                `,
                [
                    examId,
                    studentId
                ]
            );

            if (existing.length) {
                return res.json({
                    success: true,
                    attempt: existing[0],
                    message: "Existing attempt found"
                });
            }

            const [result] = await pool.query(
                `
                INSERT INTO cbt_attempts
                (
                    exam_id,
                    student_id,
                    score,
                    completed
                )
                VALUES (?, ?, 0, FALSE)
                `,
                [
                    examId,
                    studentId
                ]
            );

            res.json({
                success: true,
                attemptId: result.insertId
            });

        } catch (error) {
            console.error(error);

            res.status(500).json({
                message: "Failed to start exam"
            });
        }
    }
);

/* =========================
   TEACHER READ ONLY
========================= */

app.get(
    "/teacher/students",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    id,
                    name,
                    class,
                    age,
                    user_id
                FROM students
                ORDER BY name ASC
            `);

            res.json({
                students: rows
            });

        } catch (error) {
            res.status(500).json({
                message: "Failed to load students"
            });
        }
    }
);

app.get(
    "/teacher/results",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT
                    r.*,
                    s.name AS student_name
                FROM results r
                LEFT JOIN students s
                    ON r.student_id = s.id
                ORDER BY r.id DESC
            `);

            res.json({
                results: rows
            });

        } catch (error) {
            res.status(500).json({
                message: "Failed to load results"
            });
        }
    }
);

app.get(
    "/teacher/exams",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(`
                SELECT *
                FROM exams
                ORDER BY id DESC
            `);

            res.json({
                exams: rows
            });

        } catch (error) {
            res.status(500).json({
                message: "Failed to load exams"
            });
        }
    }
);

app.get(
    "/teacher/questions/:examId",
    auth,
    teacherOnly,
    async (req, res) => {
        try {
            const [rows] = await pool.query(
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
                ORDER BY id ASC
                `,
                [req.params.examId]
            );

            res.json({
                questions: rows
            });

        } catch (error) {
            res.status(500).json({
                message: "Failed to load questions"
            });
        }
    }
);

/* =========================
   404
========================= */

app.use((req, res) => {
    res.status(404).json({
        message: "Route not found",
        route: req.originalUrl
    });
});

/* =========================
   START SERVER
========================= */

async function startServer() {
    try {
        await pool.query("SELECT 1");

        console.log("=================================");
        console.log(" SCHOOL SYSTEM SERVER");
        console.log("=================================");
        console.log("Database: CONNECTED");
        console.log(`Server: http://localhost:${PORT}`);
        console.log(`Login: http://localhost:${PORT}/login.html`);
        console.log(`Admin: http://localhost:${PORT}/admin.html`);
        console.log(`Student: http://localhost:${PORT}/student.html`);
        console.log(`Teacher: http://localhost:${PORT}/teacher.html`);
        console.log("=================================");

        app.listen(PORT, () => {
            console.log(
                `Server running on http://localhost:${PORT}`
            );
        });

    } catch (error) {
        console.error(
            "DATABASE CONNECTION FAILED:",
            error.message
        );

        process.exit(1);
    }
}

startServer();