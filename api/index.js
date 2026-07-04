require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Groq = require('groq-sdk');
const cors = require('cors');


const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const db = mysql.createPool({
    host: 'safe-space-saffe-space.j.aivencloud.com',
    port: 10399,
    user: 'avnadmin',
    password: process.env.DB_PASSWORD,
    database: 'defaultdb',
    ssl: {
        rejectUnauthorized: false
    },
    waitForConnections: true,
    connectionLimit: 1,
    queueLimit: 0,
    connectTimeout: 10000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

db.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to Aiven:', err.message);
    } else {
        console.log('Connected to Aiven MySQL successfully!');
        connection.release();
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).send("You must be logged in first");

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.status(403).send("Token is invalid or expired");
        req.user = user;
        next();
    });
};

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'mental.health.auth@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});

// --- 1. Register ---
app.post('/register', async (req, res) => {
    const { FullName, Email, password, Phone, Gender, DateOfBirth, onboarding } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(Email)) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter a valid email address"
        });
    }

    const phoneRegex = /^01[0125][0-9]{8}$/;
    if (!phoneRegex.test(Phone)) {
        return res.status(400).json({
            status: "failed",
            message: "Invalid phone number (must be an 11-digit Egyptian number)"
        });
    }

    const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            status: "failed",
            message: "Weak password (min 8 characters, uppercase, lowercase, number, symbol)"
        });
    }

    const validGenders = ['male', 'female'];
    if (!validGenders.includes(Gender?.toLowerCase())) {
        return res.status(400).json({
            status: "failed",
            message: "Gender must be male or female"
        });
    }

    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(DateOfBirth) || isNaN(new Date(DateOfBirth).getTime())) {
        return res.status(400).json({
            status: "failed",
            message: "Invalid date of birth format (YYYY-MM-DD)"
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

        const sql = `INSERT INTO users (FullName, Email, password, Phone, Gender, DateOfBirth, verification_code, is_verified) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 0)`;

        db.execute(sql, [FullName, Email, hashedPassword, Phone, Gender.toLowerCase(), DateOfBirth, otpCode], (err, userResult) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({
                        status: "failed",
                        message: "This email is already registered"
                    });
                }
                return res.status(500).json({
                    status: "failed",
                    message: err.message
                });
            }

            const newUserId = userResult.insertId;

            const sendVerificationEmailAndRespond = () => {
                const mailOptions = {
                    from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                    to: Email,
                    subject: 'Your Account Verification Code - OTP',
                    text: `Welcome! Your verification code is: ${otpCode}`,
                    html: `
                        <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 20px; overflow: hidden; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
                            <div style="background-color: #eff6ff; padding: 35px 20px; text-align: center;">
                                <div style="font-size: 26px; font-weight: bold; color: #1e40af; margin-bottom: 10px; letter-spacing: 0.5px;">
                                    Mental Health Support
                                </div>
                                <div style="width: 60px; height: 3px; background-color: #3b82f6; margin: 0 auto; border-radius: 10px;"></div>
                            </div>
                            <div style="padding: 45px 35px; text-align: center;">
                                <h2 style="color: #0f172a; font-size: 22px; margin-bottom: 20px;">Welcome to your new journey</h2>
                                <p style="color: #475569; font-size: 16px; line-height: 1.8; margin-bottom: 35px;">
                                    We are here to support you. To secure your account and start using the platform, please enter the following verification code:
                                </p>
                                <div style="background-color: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 16px; padding: 25px; display: inline-block; min-width: 200px; margin-bottom: 35px;">
                                    <span style="font-size: 40px; font-weight: 900; letter-spacing: 10px; color: #2563eb; font-family: 'Courier New', Courier, monospace;">
                                        ${otpCode}
                                    </span>
                                </div>
                                <p style="color: #94a3b8; font-size: 14px; margin-bottom: 0;">
                                    This code expires in 10 minutes.
                                </p>
                            </div>
                            <div style="background-color: #f8fafc; padding: 25px; text-align: center; border-top: 1px solid #f1f5f9;">
                                <p style="color: #64748b; font-size: 13px; margin: 0;">
                                    A small step today means a lot for a better tomorrow.
                                </p>
                                <div style="margin-top: 15px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
                                    <p style="color: #94a3b8; font-size: 11px; margin-top: 10px;">
                                        © 2026 Mental Health Support Team
                                    </p>
                                </div>
                            </div>
                        </div>
                    `
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error("❌ Failed to send email:", error.message);
                        return res.status(201).json({
                            status: "failed",
                            message: "Account created, but failed to send verification code.",
                            error: error.message
                        });
                    }
                    console.log("✅ Email sent successfully:", info.response);
                    res.status(201).json({
                        status: "success",
                        message: "Account created successfully. Please check your email to activate your account.",
                        debug_otp: otpCode
                    });
                });
            };

            if (onboarding && onboarding.allScores) {
                const testSql = `INSERT INTO recommended_tests 
                    (user_id, score_depression, score_anxiety, score_adhd, score_ocd, score_ptsd, highest_score, recommended_tests, has_tie) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

                const testValues = [
                    newUserId,
                    onboarding.allScores.depression || 0,
                    onboarding.allScores.anxiety || 0,
                    onboarding.allScores.adhd || 0,
                    onboarding.allScores.ocd || 0,
                    onboarding.allScores.ptsd || 0,
                    onboarding.highestScore,
                    onboarding.recommendedTests.join(','),
                    onboarding.hasTie ? 1 : 0
                ];

                db.execute(testSql, testValues, (testErr) => {
                    if (testErr) {
                        console.error("❌ Failed to save recommended tests:", testErr.message);
                    } else {
                        console.log("✅ Recommended tests saved successfully for user:", newUserId);
                    }
                    sendVerificationEmailAndRespond();
                });
            } else {
                console.log("ℹ️ No onboarding data received, skipping save.");
                sendVerificationEmailAndRespond();
            }
        });
    } catch (error) {
        res.status(500).json({
            status: "failed",
            message: "Internal server error"
        });
    }
});

// --- 2. Verify OTP ---
app.post('/verify', (req, res) => {
    const { Email, code } = req.body;

    if (!Email || !code) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter your email and verification code"
        });
    }

    const sql = "SELECT * FROM users WHERE Email = ? AND verification_code = ?";
    db.execute(sql, [Email, code], (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        if (results.length === 0) {
            return res.status(400).json({
                status: "failed",
                message: "Invalid or expired verification code"
            });
        }

        const updateSql = "UPDATE users SET is_verified = 1, verification_code = NULL WHERE Email = ?";
        db.execute(updateSql, [Email], (upErr) => {
            if (upErr) {
                return res.status(500).json({
                    status: "failed",
                    message: upErr.message
                });
            }

            res.status(200).json({
                status: "success",
                message: "Account verified successfully!"
            });
        });
    });
});

// --- 3. Login ---
app.post('/login', (req, res) => {
    const { Email, password } = req.body;

    if (!Email || !password) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter your email and password"
        });
    }

    const sql = "SELECT * FROM users WHERE Email = ?";
    db.execute(sql, [Email], async (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "User not found"
            });
        }

        const user = results[0];

        if (user.is_verified === 0) {
            return res.status(403).json({
                status: "failed",
                message: "Please verify your account first"
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                status: "failed",
                message: "Incorrect password"
            });
        }

        const token = jwt.sign({ id: user.UserID }, 'secret_key');

        const statsSql = `
            SELECT 
                COUNT(tr.TestResultID) AS totalTests,
                (
                    SELECT tr2.ResultValue 
                    FROM testresults tr2 
                    WHERE tr2.UserID = ? 
                    ORDER BY tr2.ResultDate DESC 
                    LIMIT 1
                ) AS lastScore,
                (
                    SELECT tt.TotalQuestions * 3
                    FROM testresults tr2 
                    JOIN testtypes tt ON tr2.TestTypeID = tt.TestTypeID
                    WHERE tr2.UserID = ? 
                    ORDER BY tr2.ResultDate DESC 
                    LIMIT 1
                ) AS lastMaxScore
            FROM testresults tr
            WHERE tr.UserID = ?
        `;

        db.execute(statsSql, [user.UserID, user.UserID, user.UserID], (statsErr, statsResults) => {
            if (statsErr) {
                return res.status(500).json({
                    status: "failed",
                    message: "Error fetching test statistics: " + statsErr.message
                });
            }

            const stats = statsResults[0];
            const totalTests = stats ? stats.totalTests : 0;
            const lastScore = stats ? stats.lastScore : null;
            const lastMaxScore = stats ? stats.lastMaxScore : null;

            let lastScorePercentage = null;
            if (lastScore !== null && lastMaxScore !== null && lastMaxScore > 0) {
                lastScorePercentage = Math.round((lastScore / lastMaxScore) * 100);
            }

            res.status(200).json({
                status: "success",
                message: "Logged in successfully",
                token: token,
                user: {
                    id: user.UserID,
                    name: user.FullName,
                    email: user.Email,
                    phone: user.Phone,
                    gender: user.Gender,
                    dateOfBirth: user.DateOfBirth
                },
                stats: {
                    totalTests: totalTests,
                    lastScore: lastScorePercentage,
                    lastScorePercentage: lastScorePercentage
                }
            });
        });
    });
});

// --- Get Doctors List ---
app.get('/doctors', (req, res) => {
    const sql = "SELECT * FROM doctors ORDER BY CreatedAt DESC";

    db.execute(sql, (err, results) => {
        if (err) {
            console.error("❌ Error fetching doctors:", err.message);
            return res.status(500).json({
                status: "failed",
                message: "Server error while fetching data"
            });
        }

        res.status(200).json({
            status: "success",
            success: true,
            count: results.length,
            data: results
        });
    });
});

// --- Get Single Doctor ---
app.get('/doctors/:id', (req, res) => {
    const doctorId = req.params.id;
    const sql = "SELECT * FROM doctors WHERE DoctorID = ?";

    db.execute(sql, [doctorId], (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "Doctor not found"
            });
        }

        res.status(200).json({
            status: "success",
            data: results[0]
        });
    });
});

// --- Add Test Result ---
app.post('/test-results', authenticateToken, (req, res) => {
    const { TestTypeID, ResultValue } = req.body;
    const UserID = req.user.id;

    if (!TestTypeID || ResultValue === undefined) {
        return res.status(400).json({
            status: "failed",
            message: "Please provide the test type and result"
        });
    }

    const sql = "INSERT INTO testresults (UserID, TestTypeID, ResultValue) VALUES (?, ?, ?)";

    db.execute(sql, [UserID, TestTypeID, ResultValue], (err, result) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        res.status(201).json({
            status: "success",
            message: "Test result added successfully"
        });
    });
});

// --- Get Test Results ---
app.get('/test-results', authenticateToken, (req, res) => {
    const UserID = req.user.id;

    const sql = `
    SELECT 
        tr.TestResultID, 
        tr.ResultValue, 
        tr.ResultDate, 
        tt.TestName
    FROM testresults tr
    JOIN testtypes tt ON tr.TestTypeID = tt.TestTypeID
    WHERE tr.UserID = ? 
    ORDER BY tr.ResultDate DESC
`;

    db.execute(sql, [UserID], (err, results) => {
        if (err) {
            console.error("❌ Query error:", err.message);
            return res.status(500).json({
                status: "failed",
                message: "Error fetching data from the database"
            });
        }

        res.status(200).json({
            status: "success",
            success: true,
            count: results.length,
            data: results
        });
    });
});

app.post('/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const UserID = req.user.id;

        // 1. التحقق من أن الرسالة ليست فارغة
        if (!message || message.trim() === "") {
            return res.status(400).json({
                status: "failed",
                success: false,
                reply: "Message is empty, please write something."
            });
        }

        // 2. حماية من الرسائل الطويلة جداً لتوفير التكلفة ومنع إساءة الاستخدام
        if (message.length > 1500) {
            return res.status(400).json({
                status: "failed",
                success: false,
                reply: "Your message is too long. Please keep it under 1500 characters."
            });
        }

        // 3. نظام كشف كلمات الأزمات الطارئة (طبقة أمان أولى)
        const crisisKeywords = ["انتحار", "اموت", "أموت", "أأذي نفسي", "اذي نفسي", "مش عايز أعيش", "مش عايز اعيش"];
        const isCrisis = crisisKeywords.some(word => message.includes(word));

        // 4. جلب آخر 8 محادثات كاملة (يوزر + AI) من قاعدة البيانات للحفاظ على السياق
        const HISTORY_LIMIT = 8;
        const historySql = `
            SELECT UserMessage, AiResponse 
            FROM chatMessages 
            WHERE UserID = ? 
            ORDER BY MessageID DESC 
            LIMIT ?
        `;

        db.execute(historySql, [UserID, HISTORY_LIMIT], async (err, rows) => {
            if (err) {
                console.error("❌ Error fetching chat history:", err.message);
            }

            // ترتيب الرسائل من الأقدم إلى الأحدث ليقرأها الموديل بشكل صحيح
            const orderedHistory = (rows || []).reverse();

            // 5. الـ System Prompt الثابت والمحسن لتوجيه الموديل بدقة
            const systemPrompt = `You are an advanced AI mental health support assistant integrated into a mobile application.
Your role is to provide emotional support, identify possible emotional patterns, and guide users toward self-assessment tools available in the app (not medical diagnosis tools).
You support users experiencing symptoms related to: Depression, Anxiety, OCD, ADHD, PTSD.

CONVERSATION AWARENESS:
- You are talking to the user in a continuous conversation. Read the history provided.
- If the user already shared something (a feeling, an event, a name), refer back to it naturally instead of asking again.
- If the user's message is short or vague (e.g. "ايه؟", "ليه؟", "مش فاهم"), interpret it strictly in light of the previous exchange.
- Avoid repeating the same opening phrases, greetings, or suggesting the same test repeatedly.

CORE BEHAVIOR:
1. Always respond with empathy, warmth, and non-judgment in simple Egyptian Arabic dialect.
2. Gently suggest relevant self-assessment tests in the app based on their symptoms (sadness -> Depression test, worry -> Anxiety test, distraction -> ADHD test, repetitive behavior -> OCD test). Use soft language.
3. NEVER diagnose or give scores/percentages. Say "You may be experiencing symptoms similar to..."
4. Keep responses short, calming, and supportive. Avoid medical jargon.
5. If the user expresses self-harm or severe distress, prioritize immediate empathy and encourage reaching out to a trusted person or professional help.`;

            // 6. بناء مصفوفة الرسائل (Messages Array) الموجهة للـ API بشكل منظم
            const messages = [{ role: "system", content: systemPrompt }];

            // دفع التاريخ بترتيب صحيح وسليم (مستخدم ثم مساعد)
            orderedHistory.forEach(row => {
                messages.push({ role: "user", content: row.UserMessage });
                messages.push({ role: "assistant", content: row.AiResponse });
            });

            // دفع الرسالة الحالية الجديدة في نهاية المصفوفة
            messages.push({ role: "user", content: message });

            try {
                // 7. الاتصال بـ Groq API باستخدام موديل Llama 3.3
                const result = await groq.chat.completions.create({
                    model: "llama-3.3-70b-versatile",
                    messages,
                    max_tokens: 800, 
                    temperature: 0.5 // درجة حرارة متزنة تضمن الالتزام بالتعليمات واللهجة دون تخريف
                });

                let aiText = result.choices[0].message.content;

                // 8. إذا تم رصد أزمة نفسية خطيرة، يتم إرفاق أرقام الدعم النفسي الرسمية بمصر تلقائياً
                if (isCrisis && !aiText.includes("تتواصل")) {
                    aiText += "\n\nلو حاسس إنك مش قادر تتحمل، ياريت تتواصل مع حد قريب منك دلوقتي أو بخط المساعدة النفسية (16463 أو 0220816831 في مصر). إنت مش لوحدك في ده.";
                }

                // 9. حفظ الرسالة الجديدة والرد الخاص بالـ AI في قاعدة البيانات
                const insertSql = "INSERT INTO chatMessages (UserID, UserMessage, AiResponse) VALUES (?, ?, ?)";
                db.execute(insertSql, [UserID, message, aiText], (err) => {
                    if (err) console.error("❌ Error saving message:", err.message);

                    // 10. إرسال الرد النهائي للمستخدم
                    res.status(200).json({
                        status: "success",
                        success: true,
                        reply: aiText
                    });
                });
            } catch (groqError) {
                console.error("Groq Error:", groqError);
                // التعامل مع تخطي حدود الاستخدام المتزامن (Rate Limit)
                if (groqError.status === 429) {
                    return res.status(503).json({
                        status: "failed",
                        success: false,
                        reply: "Server is busy, please try again in a few seconds."
                    });
                }
                res.status(500).json({
                    status: "failed",
                    success: false,
                    reply: "An error occurred while communicating with the AI"
                });
            }
        });

    } catch (error) {
        console.error("General Error:", error);
        res.status(500).json({
            status: "failed",
            success: false,
            reply: "An error occurred"
        });
    }
});

// --- 4. Forgot Password ---
app.post('/forgot-password', (req, res) => {
    const { Email } = req.body;

    if (!Email) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter your email address"
        });
    }

    const sqlCheck = "SELECT * FROM users WHERE Email = ? AND is_verified = 1";
    db.execute(sqlCheck, [Email], (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }
        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "This email is not registered or not verified"
            });
        }

        const resetOtpCode = Math.floor(100000 + Math.random() * 900000).toString();

        const sqlInsertReset = "REPLACE INTO password_resets (Email, token_code) VALUES (?, ?)";
        db.execute(sqlInsertReset, [Email, resetOtpCode], (upErr) => {
            if (upErr) {
                return res.status(500).json({
                    status: "failed",
                    message: upErr.message
                });
            }

            const mailOptions = {
                from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                to: Email,
                subject: 'Password Reset - OTP',
                html: `
                    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 20px; overflow: hidden; background-color: #ffffff;">
                        <div style="background-color: #fef2f2; padding: 35px 20px; text-align: center;">
                            <h1 style="color: #dc2626; margin: 0;">Password Reset</h1>
                        </div>
                        <div style="padding: 45px 35px; text-align: center;">
                            <p style="color: #475569; font-size: 16px;">Your verification code (valid for 10 minutes):</p>
                            <div style="background-color: #f8fafc; border: 1px dashed #cbd5e1; padding: 25px; display: inline-block; min-width: 200px; margin-bottom: 20px;">
                                <span style="font-size: 40px; font-weight: bold; color: #dc2626; letter-spacing: 10px; font-family: monospace;">${resetOtpCode}</span>
                            </div>
                        </div>
                    </div>`
            };

            transporter.sendMail(mailOptions, (mailErr) => {
                if (mailErr) {
                    return res.status(500).json({
                        status: "failed",
                        message: "Failed to send email, please try again later"
                    });
                }

                res.status(200).json({
                    status: "success",
                    success: true,
                    message: "Reset code sent successfully.",
                    debug_otp: resetOtpCode
                });
            });
        });
    });
});

// --- 5. Verify Reset Code ---
app.post('/verify-reset-code', (req, res) => {
    const { Email, code } = req.body;

    if (!Email || !code) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter your email and the code"
        });
    }

    const sql = "SELECT *, TIMESTAMPDIFF(MINUTE, CreatedAt, NOW()) AS minutes_passed FROM password_resets WHERE Email = ?";
    db.execute(sql, [Email], (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }
        if (results.length === 0) {
            return res.status(400).json({
                status: "failed",
                message: "No reset code was requested for this email or it has expired"
            });
        }

        const record = results[0];

        if (record.minutes_passed > 10) {
            db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);
            return res.status(400).json({
                status: "failed",
                message: "This code has expired (10 minutes passed), please request a new one"
            });
        }

        if (record.token_code !== code) {
            return res.status(400).json({
                status: "failed",
                message: "Incorrect code"
            });
        }

        db.execute("UPDATE password_resets SET token_code = 'VERIFIED' WHERE Email = ?", [Email], (verErr) => {
            if (verErr) {
                return res.status(500).json({
                    status: "failed",
                    message: verErr.message
                });
            }

            res.status(200).json({
                status: "success",
                success: true,
                message: "Code verified successfully. You can now set a new password."
            });
        });
    });
});

// --- 6. Reset Password ---
app.put('/reset-password', async (req, res) => {
    const { Email, password } = req.body;

    if (!Email || !password) {
        return res.status(400).json({
            status: "failed",
            message: "Required data is incomplete"
        });
    }

    const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            status: "failed",
            message: "Weak password (min 8 characters, uppercase, lowercase, number)"
        });
    }

    const sqlCheckUser = "SELECT * FROM users WHERE Email = ?";
    db.execute(sqlCheckUser, [Email], (userErr, userResults) => {
        if (userErr) {
            return res.status(500).json({
                status: "failed",
                message: userErr.message
            });
        }

        if (userResults.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "This email is not registered, please create an account first"
            });
        }

        const sqlCheckReset = "SELECT *, TIMESTAMPDIFF(MINUTE, CreatedAt, NOW()) AS minutes_passed FROM password_resets WHERE Email = ? AND token_code = 'VERIFIED'";
        db.execute(sqlCheckReset, [Email], async (resetErr, resetResults) => {
            if (resetErr) {
                return res.status(500).json({
                    status: "failed",
                    message: resetErr.message
                });
            }

            if (resetResults.length === 0 || resetResults[0].minutes_passed > 10) {
                db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);
                return res.status(403).json({
                    status: "failed",
                    message: "Unauthorized request or the 10-minute window has expired, please start over"
                });
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);

                const sqlUpdateUser = "UPDATE users SET password = ? WHERE Email = ?";
                db.execute(sqlUpdateUser, [hashedPassword, Email], (upErr) => {
                    if (upErr) {
                        return res.status(500).json({
                            status: "failed",
                            message: upErr.message
                        });
                    }

                    db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);

                    res.status(200).json({
                        status: "success",
                        success: true,
                        message: "Password changed successfully! You can now log in."
                    });
                });
            } catch (error) {
                res.status(500).json({
                    status: "failed",
                    message: "Server error while encrypting the password"
                });
            }
        });
    });
});

// --- Get Chat History ---
app.get('/chat/history', authenticateToken, (req, res) => {
    const UserID = req.user.id;

    const sql = "SELECT UserMessage, AiResponse, CreatedAt FROM chatMessages WHERE UserID = ? ORDER BY CreatedAt ASC";

    db.execute(sql, [UserID], (err, results) => {
        if (err) {
            console.error("❌ Error fetching chat history:", err.message);
            return res.status(500).json({
                status: "failed",
                message: "Failed to load previous conversations"
            });
        }

        res.status(200).json({
            status: "success",
            success: true,
            history: results
        });
    });
});

// --- Get Tests List ---
app.get('/tests', (req, res) => {
    const authHeader = req.headers.authorization;
    let userId = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, 'secret_key');
            userId = decoded.UserID || decoded.id;
        } catch (jwtErr) {
            console.log("ℹ️ Invalid or expired token, treating as guest visitor.");
        }
    }

    let sql = "";
    let queryParams = [];

    if (userId) {
        sql = `
            SELECT 
                t.TestTypeID, 
                t.TestName, 
                t.Description, 
                t.NormalRange, 
                t.TotalQuestions,
                CASE 
                    WHEN r.recommended_tests IS NOT NULL 
                    AND FIND_IN_SET(
                        LOWER(TRIM(CONVERT(t.TestName USING utf8mb4) COLLATE utf8mb4_unicode_ci)),
                        LOWER(REPLACE(CONVERT(r.recommended_tests USING utf8mb4) COLLATE utf8mb4_unicode_ci, ' ', ''))
                    ) > 0 
                    THEN true
                    ELSE false
                END AS isRecommended
            FROM testtypes t
            LEFT JOIN recommended_tests r ON r.user_id = ?
            ORDER BY isRecommended DESC, t.TestTypeID ASC;
        `;
        queryParams = [userId];
    } else {
        sql = `
            SELECT 
                TestTypeID, 
                TestName, 
                Description, 
                NormalRange, 
                TotalQuestions,
                false AS isRecommended
            FROM testtypes
            ORDER BY TestTypeID ASC;
        `;
    }

    db.execute(sql, queryParams, (err, results) => {
        if (err) {
            console.error("❌ Error fetching tests:", err.message);
            return res.status(500).json({
                status: "failed",
                success: false,
                message: "Server error while fetching data"
            });
        }

        const formattedResults = results.map(test => ({
            ...test,
            isRecommended: !!test.isRecommended
        }));

        res.status(200).json({
            status: "success",
            success: true,
            count: formattedResults.length,
            tests: formattedResults
        });
    });
});

// --- Get Single Test ---
app.get('/tests/:testId', (req, res) => {
    const testId = req.params.testId;

    if (!testId || isNaN(testId)) {
        return res.status(400).json({
            status: "failed",
            success: false,
            message: "Invalid or missing test ID"
        });
    }

    const testSql = "SELECT TestTypeID, TestName, Description, NormalRange, TotalQuestions FROM testtypes WHERE TestTypeID = ?";

    db.execute(testSql, [testId], (testErr, testResults) => {
        if (testErr) {
            console.error(`❌ Error fetching test #${testId}:`, testErr.message);
            return res.status(500).json({
                status: "failed",
                success: false,
                message: "Server error while fetching test data"
            });
        }

        if (testResults.length === 0) {
            return res.status(404).json({
                status: "failed",
                success: false,
                message: "This test does not exist"
            });
        }

        const testInfo = testResults[0];

        const questionsSql = "SELECT QuestionID, QuestionText FROM questions WHERE TestTypeID = ? ORDER BY QuestionID ASC";

        db.execute(questionsSql, [testId], (qErr, qResults) => {
            if (qErr) {
                console.error(`❌ Error fetching questions for test #${testId}:`, qErr.message);
                return res.status(500).json({
                    status: "failed",
                    success: false,
                    message: "Server error while fetching test questions"
                });
            }

            res.status(200).json({
                status: "success",
                success: true,
                test_details: {
                    id: testInfo.TestTypeID,
                    name: testInfo.TestName,
                    description: testInfo.Description,
                    normal_range: testInfo.NormalRange,
                    total_questions_expected: testInfo.TotalQuestions
                },
                questions_data: {
                    total_questions_found: qResults.length,
                    questions: qResults
                }
            });
        });
    });
});

// --- Change Password ---
app.put('/change-password', protect, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    
    // 1. التوكن بيفك الـ ID اللي إنت مخزنه في اللوجين (id: user.UserID)
    const userId = req.user.id; 

    // 2. التأكد إن الحقول مش فاضية
    if (!oldPassword || !newPassword) {
        return res.status(400).json({
            status: "failed",
            message: "Please enter your old and new password"
        });
    }

    // 3. الـ Regex القوي: 8 حروف على الأقل، حرف كبير، حرف صغير، ورقم
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
            status: "failed",
            message: "New password is too weak! Must be at least 8 characters, with 1 uppercase, 1 lowercase, and 1 number."
        });
    }

    // 4. نجيب الباسورد الحالي من الداتا بيز بنفس أسلوب اللوجين بتاعك
    const sql = "SELECT password FROM users WHERE UserID = ?";
    db.execute(sql, [userId], async (err, results) => {
        if (err) {
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "User not found"
            });
        }

        const user = results[0];

        // 5. مقارنة الباسورد القديم باللي في الداتا بيز بـ bcrypt.compare زي اللوجين
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({
                status: "failed",
                message: "Incorrect old password"
            });
        }

        // 6. تشفير الباسورد الجديد قبل الحفظ
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        // 7. تحديث الداتا بيز بالباسورد المتشفر الجديد
        const updateSql = "UPDATE users SET password = ? WHERE UserID = ?";
        db.execute(updateSql, [hashedNewPassword, userId], (updateErr, updateResults) => {
            if (updateErr) {
                return res.status(500).json({
                    status: "failed",
                    message: updateErr.message
                });
            }

            // كله تمام والعملية نجحت
            return res.status(200).json({
                status: "success",
                message: "Password changed successfully"
            });
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
module.exports = app;