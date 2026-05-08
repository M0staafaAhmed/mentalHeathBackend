require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Groq = require('groq-sdk');

const app = express();
app.use(express.json());

// إعداد Groq
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// --- إعدادات الاتصال بـ Aiven ---
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
    connectionLimit: 10,
    queueLimit: 0
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

    if (!token) return res.status(401).send("يجب تسجيل الدخول أولاً");

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.status(403).send("التوكن غير صالح أو انتهى");
        req.user = user;
        next();
    });
};

// --- إعداد مرسل الإيميلات (OTP) ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'mental.health.auth@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});

// --- 1. تسجيل حساب جديد (Register) ---
app.post('/register', async (req, res) => {
    const { FullName, Email, password, Phone, Gender, DateOfBirth } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(Email)) return res.status(400).send("برجاء إدخال بريد إلكتروني صحيح");

    const phoneRegex = /^01[0125][0-9]{8}$/;
    if (!phoneRegex.test(Phone)) return res.status(400).send("رقم التليفون غير صحيح (11 رقم مصري)");

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
    if (!passwordRegex.test(password)) return res.status(400).send("كلمة السر ضعيفة (8 حروف، حرف كبير، حرف صغير، رقم)");

    const validGenders = ['male', 'female'];
    if (!validGenders.includes(Gender?.toLowerCase())) return res.status(400).send("يجب اختيار male أو female");

    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(DateOfBirth) || isNaN(new Date(DateOfBirth).getTime())) {
        return res.status(400).send("تنسيق تاريخ الميلاد غير صحيح (YYYY-MM-DD)");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

        const sql = `INSERT INTO users (FullName, Email, password, Phone, Gender, DateOfBirth, verification_code, is_verified) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 0)`;

        db.execute(sql, [FullName, Email, hashedPassword, Phone, Gender.toLowerCase(), DateOfBirth, otpCode], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).send("الايميل موجود بالفعل");
                return res.status(500).send(err.message);
            }

            const mailOptions = {
                from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                to: Email,
                subject: 'كود تفعيل حسابك - OTP',
                text: `أهلاً بك، كود التفعيل الخاص بك هو: ${otpCode}`,
                html: `
                <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e7ff; border-radius: 16px; overflow: hidden; background-color: #ffffff;">
                    <!-- Header -->
                    <div style="background-color: #f0fdf4; padding: 30px; text-align: center;">
                        <div style="font-size: 24px; font-weight: bold; color: #166534; margin-bottom: 10px;">
                            Mental Health Support
                        </div>
                        <div style="width: 50px; height: 4px; background-color: #22c55e; margin: 0 auto; border-radius: 2px;"></div>
                    </div>

                    <!-- Body -->
                    <div style="padding: 40px 30px; text-align: center;">
                        <h2 style="color: #1e293b; margin-bottom: 20px;">مرحباً بك!</h2>
                        <p style="color: #64748b; font-size: 16px; line-height: 1.6; margin-bottom: 30px;">
                            لقد بدأت خطوة رائعة للاهتمام بصحتك النفسية. لتأكيد حسابك، يرجى استخدام رمز التحقق (OTP) التالي:
                        </p>
                        
                        <div style="background-color: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 12px; padding: 20px; display: inline-block; margin-bottom: 30px;">
                            <span style="font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #16a34a; font-family: monospace;">
                                ${otpCode}
                            </span>
                        </div>

                        <p style="color: #94a3b8; font-size: 14px;">
                            هذا الكود صالح لمدة 10 دقائق فقط. إذا لم تكن أنت من طلب هذا الرمز، يمكنك تجاهل هذا البريد.
                        </p>
                    </div>

                    <!-- Footer -->
                    <div style="background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #f1f5f9;">
                        <p style="color: #94a3b8; font-size: 12px; margin: 0;">
                            مع كل التمنيات لك بالهدوء والراحة النفسية
                        </p>
                        <p style="color: #94a3b8; font-size: 12px; margin-top: 5px;">
                            © ${new Date().getFullYear()} Mental Health Support Team
                        </p>
                    </div>
                </div>
                `
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error("❌ فشل إرسال الإيميل:", error.message);
                    return res.status(201).json({
                        message: "تم إنشاء الحساب، ولكن فشل إرسال كود التفعيل.",
                        error: error.message
                    });
                }

                console.log("✅ تم إرسال الإيميل بنجاح:", info.response);
                res.status(201).json({
                    message: "تم إنشاء الحساب بنجاح. برجاء فحص إيميلك لتفعيل الحساب.",
                    debug_otp: otpCode
                });
            });
        });
    } catch (error) {
        res.status(500).send("خطأ في السيرفر");
    }
});

// --- 2. تفعيل الحساب (Verify OTP) ---
app.post('/verify', (req, res) => {
    const { Email, code } = req.body;

    const sql = "SELECT * FROM users WHERE Email = ? AND verification_code = ?";
    db.execute(sql, [Email, code], (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(400).send("الكود غير صحيح");

        const updateSql = "UPDATE users SET is_verified = 1, verification_code = NULL WHERE Email = ?";
        db.execute(updateSql, [Email], (upErr) => {
            if (upErr) return res.status(500).send(upErr.message);
            res.send("تم تفعيل الحساب بنجاح!");
        });
    });
});

// --- 3. تسجيل الدخول (Login) ---
app.post('/login', (req, res) => {
    const { Email, password } = req.body;

    const sql = "SELECT * FROM users WHERE Email = ?";
    db.execute(sql, [Email], async (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(404).send("المستخدم غير موجود");

        const user = results[0];

        if (user.is_verified === 0) return res.status(403).send("برجاء تفعيل الحساب أولاً");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send("كلمة السر خطأ");

        const token = jwt.sign({ id: user.UserID }, 'secret_key')

        res.json({
            message: "تم تسجيل الدخول بنجاح",
            token: token,
            user: { id: user.UserID, name: user.FullName }
        });
    });
});

// --- عرض قائمة الأطباء ---
app.get('/doctors', (req, res) => {
    const sql = "SELECT * FROM doctors ORDER BY CreatedAt DESC";

    db.execute(sql, (err, results) => {
        if (err) {
            console.error("❌ خطأ في جلب بيانات الأطباء:", err.message);
            return res.status(500).send("خطأ في السيرفر عند جلب البيانات");
        }

        res.status(200).json({
            success: true,
            count: results.length,
            data: results
        });
    });
});

// --- عرض طبيب واحد ---
app.get('/doctors/:id', (req, res) => {
    const doctorId = req.params.id;
    const sql = "SELECT * FROM doctors WHERE DoctorID = ?";

    db.execute(sql, [doctorId], (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(404).send("الطبيب غير موجود");

        res.status(200).json(results[0]);
    });
});

// --- إضافة نتيجة اختبار ---
app.post('/test-results', authenticateToken, (req, res) => {
    const { TestTypeID, ResultValue } = req.body;
    const UserID = req.user.id;

    const sql = "INSERT INTO testresults (UserID, TestTypeID, ResultValue) VALUES (?, ?, ?)";

    db.execute(sql, [UserID, TestTypeID, ResultValue], (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.status(201).json({ message: "تم إضافة نتيجة الاختبار بنجاح" });
    });
});

// --- عرض نتائج الاختبارات ---
app.get('/test-results', authenticateToken, (req, res) => {
    const UserID = req.user.id;

    // استخدمنا JOIN لربط الجدولين عن طريق TestTypeID
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
            console.error("❌ خطأ في الاستعلام:", err.message);
            return res.status(500).send("خطأ في جلب البيانات من قاعدة البيانات");
        }

        res.status(200).json({
            success: true,
            count: results.length,
            data: results
        });
    });
});

// --- الشات مع Groq AI ---
app.post('/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const UserID = req.user.id;

        if (!message) return res.status(400).send("الرسالة فارغة");

        const systemPrompt = `You are an advanced AI mental health support assistant integrated into a mobile application.

                                Your role is to provide emotional support, identify possible emotional patterns, and guide users toward self-assessment tools available in the app (not medical diagnosis tools).

                                You support users experiencing symptoms related to:
                                - Depression
                                - Anxiety
                                - OCD (Obsessive Compulsive Disorder)
                                - ADHD
                                - PTSD

                                ---

                                CORE BEHAVIOR:

                                1. Emotional Support:
                                - Always respond with empathy, warmth, and non-judgment.
                                - Validate the user's feelings without labeling them as a medical condition.

                                2. Smart Guidance (VERY IMPORTANT):
                                - Based on the user's message, gently suggest the most relevant self-assessment test in the app.
                                - Do NOT force or diagnose.
                                - Use soft language like:
                                - "Based on what you're describing..."
                                - "You might benefit from trying..."
                                - "It could be helpful to take the..."

                                Examples:
                                - If user expresses sadness, hopelessness → suggest Depression test
                                - If user expresses excessive worry, panic → suggest Anxiety test
                                - If user mentions distraction, lack of focus → suggest ADHD test
                                - If user mentions intrusive thoughts or repetitive behaviors → suggest OCD test
                                - If user mentions trauma or flashbacks → suggest PTSD test

                                3. No Diagnosis Rule:
                                - Never say:
                                - "You have depression"
                                - "You are diagnosed with..."
                                - Any percentages or scores

                                Instead say:
                                - "You may be experiencing symptoms similar to..."
                                - "It could be helpful to explore..."

                                ---

                                4. Output Style:
                                - Use simple Arabic (Egyptian dialect preferred)
                                - Keep responses short, calming, and supportive
                                - Avoid medical jargon

                                ---

                                5. App Integration Goal:
                                Your main goal is to guide users toward the app's self-assessment feature.

                                When appropriate, suggest:
                                - "You can take the Depression self-assessment test in the app to better understand your feelings."
                                - "There is an Anxiety check in the app that might help you reflect on what you're feeling."

                                ---

                                6. Crisis Handling:
                                If user expresses self-harm or severe distress:
                                - Respond with immediate empathy
                                - Encourage reaching out to a trusted person or professional help
                                - Do NOT leave user alone with instructions or technical suggestions

                                ---

                                7. Final Objective:
                                Help users feel understood, emotionally supported, and gently guided toward the most relevant self-assessment tool in the app.

                                user message: ${message}`;

        // إرسال الطلب لـ Groq
        const result = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: message }
            ],
            max_tokens: 1024
        });

        const aiText = result.choices[0].message.content;

        // حفظ المحادثة في الداتابيز
        const sql = "INSERT INTO chatMessages (UserID, UserMessage, AiResponse) VALUES (?, ?, ?)";
        db.execute(sql, [UserID, message, aiText], (err) => {
            if (err) console.error("خطأ في حفظ الرسالة:", err.message);

            res.json({
                success: true,
                reply: aiText
            });
        });

    } catch (error) {
        console.error("Groq Error:", error);

        if (error.status === 429) {
            return res.status(503).json({
                success: false,
                reply: "الخدمة مشغولة حالياً، برجاء المحاولة بعد قليل 🙏"
            });
        }

        res.status(500).json({
            success: false,
            reply: "حدث خطأ في التواصل مع الذكاء الاصطناعي"
        });
    }
});


app.get('/chat/history', authenticateToken, (req, res) => {
    const UserID = req.user.id; // بناخده من التوكن لضمان الأمان

    const sql = "SELECT UserMessage, AiResponse, CreatedAt FROM chatMessages WHERE UserID = ? ORDER BY CreatedAt ASC";

    db.execute(sql, [UserID], (err, results) => {
        if (err) {
            console.error("خطأ في جلب تاريخ الشات:", err.message);
            return res.status(500).json({ error: "فشل في تحميل المحادثات القديمة" });
        }

        res.json({
            success: true,
            history: results // دي مصفوفة (Array) فيها كل الرسايل
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// ... نهاية الكود بتاعك
module.exports = app;