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
    origin: '*', // السماح لأي دومين بالوصول للـ API
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // السماح بالطرق دي
    allowedHeaders: ['Content-Type', 'Authorization'] // السماح بالرؤوس دي
}));

// إعداد Groq
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
    connectionLimit: 1,        // ← غيّرها من 10 لـ 1
    queueLimit: 0,
    connectTimeout: 10000,     // ← أضف ده
    acquireTimeout: 10000,     // ← أضف ده
    idleTimeoutMillis: 10000   // ← أضف ده
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
    // استقبلنا أوبجكت onboarding الجديد هنا مع بيانات التسجيل
    const { FullName, Email, password, Phone, Gender, DateOfBirth, onboarding } = req.body;

    // 1. التحقق من صحة الإيميل
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(Email)) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال بريد إلكتروني صحيح"
        });
    }

    // 2. التحقق من رقم التليفون
    const phoneRegex = /^01[0125][0-9]{8}$/;
    if (!phoneRegex.test(Phone)) {
        return res.status(400).json({
            status: "failed",
            message: "رقم التليفون غير صحيح (11 رقم مصري)"
        });
    }

    // 3. التحقق من قوة كلمة السر (التحديث الجديد للـ Regex شامل الرموز)
    const passwordRegex = /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            status: "failed",
            message: "كلمة السر ضعيفة (8 حروف، حرف كبير، حرف صغير، رقم، رمز)"
        });
    }

    // 4. التحقق من الجنس
    const validGenders = ['male', 'female'];
    if (!validGenders.includes(Gender?.toLowerCase())) {
        return res.status(400).json({
            status: "failed",
            message: "يجب اختيار male أو female"
        });
    }

    // 5. التحقق من تاريخ الميلاد
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(DateOfBirth) || isNaN(new Date(DateOfBirth).getTime())) {
        return res.status(400).json({
            status: "failed",
            message: "تنسيق تاريخ الميلاد غير صحيح (YYYY-MM-DD)"
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
                        message: "الايميل موجود بالفعل"
                    });
                }
                return res.status(500).json({
                    status: "failed",
                    message: err.message
                });
            }

            // 🔥 السحر هنا: طلعنا الـ UserID اللي لسه متباصي ومخلوق حالا في الداتا بيز
            const newUserId = userResult.insertId;

            // دالة الإيميل والرد النهائي معزولة في سهم عشان نشغلها بعد حفظ الأونبوردنج أو لو مفيش أونبوردنج
            const sendVerificationEmailAndRespond = () => {
                const mailOptions = {
                    from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                    to: Email,
                    subject: 'كود تفعيل حسابك - OTP',
                    text: `أهلاً بك، كود التفعيل الخاص بك هو: ${otpCode}`,
                    html: `
                        <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 20px; overflow: hidden; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
                            <div style="background-color: #eff6ff; padding: 35px 20px; text-align: center;">
                                <div style="font-size: 26px; font-weight: bold; color: #1e40af; margin-bottom: 10px; letter-spacing: 0.5px;">
                                    Mental Health Support
                                </div>
                                <div style="width: 60px; height: 3px; background-color: #3b82f6; margin: 0 auto; border-radius: 10px;"></div>
                            </div>
                            <div style="padding: 45px 35px; text-align: center;">
                                <h2 style="color: #0f172a; font-size: 22px; margin-bottom: 20px;">مرحباً بك في رحلتك الجديدة</h2>
                                <p style="color: #475569; font-size: 16px; line-height: 1.8; margin-bottom: 35px;">
                                    نحن هنا لدعمك. لضمان أمان حسابك والبدء في استخدام المنصة، يرجى إدخال رمز التحقق التالي:
                                </p>
                                <div style="background-color: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 16px; padding: 25px; display: inline-block; min-width: 200px; margin-bottom: 35px;">
                                    <span style="font-size: 40px; font-weight: 900; letter-spacing: 10px; color: #2563eb; font-family: 'Courier New', Courier, monospace;">
                                        ${otpCode}
                                    </span>
                                </div>
                                <p style="color: #94a3b8; font-size: 14px; margin-bottom: 0;">
                                    تنتهي صلاحية هذا الرمز خلال 10 دقائق.
                                </p>
                            </div>
                            <div style="background-color: #f8fafc; padding: 25px; text-align: center; border-top: 1px solid #f1f5f9;">
                                <p style="color: #64748b; font-size: 13px; margin: 0;">
                                    خطوة صغيرة اليوم، تعني الكثير لغدٍ أفضل.
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
                        console.error("❌ فشل إرسال الإيميل:", error.message);
                        return res.status(201).json({
                            status: "failed",
                            message: "تم إنشاء الحساب، ولكن فشل إرسال كود التفعيل.",
                            error: error.message
                        });
                    }
                    console.log("✅ تم إرسال الإيميل بنجاح:", info.response);
                    res.status(201).json({
                        status: "success",
                        message: "تم إنشاء الحساب بنجاح. برجاء فحص إيميلك لتفعيل الحساب.",
                        debug_otp: otpCode
                    });
                });
            };

            // ⚡ التشيك على وجود بيانات الأونبوردنج
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
                    onboarding.recommendedTests.join(','), // بنحوله لـ String مفصول بكومة ليتخزن في VARCHAR
                    onboarding.hasTie ? 1 : 0
                ];

                db.execute(testSql, testValues, (testErr) => {
                    if (testErr) {
                        console.error("❌ فشل حفظ الـ recommended tests:", testErr.message);
                        // مش هنوقف التسجيل الأساسي، هنكمل عادي عشان اليوزر ميتعطلش، بس هنطبع الـ Error للـ Debugging
                    } else {
                        console.log("✅ تم حفظ الـ recommended tests بنجاح لليوزر:", newUserId);
                    }
                    // كمل الـ Flow وابعت الميل
                    sendVerificationEmailAndRespond();
                });
            } else {
                // لو عمل Skip أو الداتا مجتش، ابعت الميل فوراً وكأن شيئاً لم يكن
                console.log("ℹ️ لم يتم إرسال بيانات onboarding، تم تخطي الحفظ.");
                sendVerificationEmailAndRespond();
            }
        });
    } catch (error) {
        res.status(500).json({
            status: "failed",
            message: "خطأ داخلي في السيرفر"
        });
    }
});

// --- 2. تفعيل الحساب (Verify OTP) ---
app.post('/verify', (req, res) => {
    const { Email, code } = req.body;

    // 1. التحقق من وجود المدخلات الأساسية
    if (!Email || !code) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال البريد الإلكتروني وكود التفعيل"
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

        // 2. إذا لم يطابق الكود أو الإيميل
        if (results.length === 0) {
            return res.status(400).json({
                status: "failed",
                message: "الكود غير صحيح أو منتهي الصلاحية"
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

            // 3. إرسال استجابة النجاح بنجاح
            res.status(200).json({
                status: "success",
                message: "تم تفعيل الحساب بنجاح!"
            });
        });
    });
});

// --- 3. تسجيل الدخول (Login) ---
app.post('/login', (req, res) => {
    const { Email, password } = req.body;

    // 1. التحقق من المدخلات الأساسية أولاً
    if (!Email || !password) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال البريد الإلكتروني وكلمة المرور"
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

        // 2. إذا لم يتم العثور على المستخدم
        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "المستخدم غير موجود"
            });
        }

        const user = results[0];

        // 3. التحقق مما إذا كان الحساب مفعلاً أم لا
        if (user.is_verified === 0) {
            return res.status(403).json({
                status: "failed",
                message: "برجاء تفعيل الحساب أولاً"
            });
        }

        // 4. مقارنة كلمة المرور
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({
                status: "failed",
                message: "كلمة السر خطأ"
            });
        }

        // 5. إنشاء الـ Token
        const token = jwt.sign({ id: user.UserID }, 'secret_key');

        // 6. استعلام لجلب إحصائيات الاختبارات للمستخدم الحالي
        // الاستعلام ده بيجيب العدد الإجمالي، وبيجيب آخر سكور عن طريق Subquery بيرتب التواريخ تنازلياً ويأخذ أول صف
        const statsSql = `
            SELECT 
                COUNT(TestResultID) AS totalTests,
                (SELECT ResultValue FROM testresults WHERE UserID = ? ORDER BY ResultDate DESC LIMIT 1) AS lastScore
            FROM testresults 
            WHERE UserID = ?
        `;

        db.execute(statsSql, [user.UserID, user.UserID], (statsErr, statsResults) => {
            if (statsErr) {
                // حتى لو حصل مشكلة هنا، ممكن تعديها أو ترجع error حسب تفضيلك، هنا هنرجع 500 للأمان
                return res.status(500).json({
                    status: "failed",
                    message: "خطأ أثناء جلب إحصائيات الاختبارات: " + statsErr.message
                });
            }

            const stats = statsResults[0];

            // إذا كان المستخدم معملش أي اختبارات قبل كده، الـ lastScore هيرجع null والـ totalTests هيرجع 0
            const totalTests = stats ? stats.totalTests : 0;
            const lastScore = stats ? stats.lastScore : null;

            // 7. إرسال استجابة النجاح المتكاملة مدمج معها بيانات الاختبارات
            res.status(200).json({
                status: "success",
                message: "تم تسجيل الدخول بنجاح",
                token: token,
                user: {
                    id: user.UserID,
                    name: user.FullName
                },
                stats: {
                    totalTests: totalTests,
                    lastScore: lastScore
                }
            });
        });
    });
});

// --- عرض قائمة الأطباء ---
app.get('/doctors', (req, res) => {
    const sql = "SELECT * FROM doctors ORDER BY CreatedAt DESC";

    db.execute(sql, (err, results) => {
        if (err) {
            console.error("❌ خطأ في جلب بيانات الأطباء:", err.message);
            // إضافة حقل status: "failed" وتوحيد نمط الاستجابة للأخطاء
            return res.status(500).json({
                status: "failed",
                message: "خطأ في السيرفر عند جلب البيانات"
            });
        }

        // استجابة النجاح بعد إضافة حقل status: "success"
        res.status(200).json({
            status: "success",
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
        if (err) {
            // إضافة حقل status: "failed" في حالة خطأ السيرفر
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        // إذا لم يتم العثور على الطبيب بالـ ID الممرر
        if (results.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "الطبيب غير موجود"
            });
        }

        // استجابة النجاح وتمرير البيانات داخل كائن موحد
        res.status(200).json({
            status: "success",
            data: results[0]
        });
    });
});

// --- إضافة نتيجة اختبار ---
app.post('/test-results', authenticateToken, (req, res) => {
    const { TestTypeID, ResultValue } = req.body;
    const UserID = req.user.id; // بناخده من التوكن لضمان الأمان

    // 1. تأكيد وجود المدخلات الأساسية
    if (!TestTypeID || ResultValue === undefined) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال نوع الاختبار والنتيجة"
        });
    }

    const sql = "INSERT INTO testresults (UserID, TestTypeID, ResultValue) VALUES (?, ?, ?)";

    db.execute(sql, [UserID, TestTypeID, ResultValue], (err, result) => {
        if (err) {
            // 2. تحويل الخطأ إلى JSON مع إضافة حقل الـ status لتوحيد الاستجابة
            return res.status(500).json({
                status: "failed",
                message: err.message
            });
        }

        // 3. استجابة النجاح الموحدة
        res.status(201).json({
            status: "success",
            message: "تم إضافة نتيجة الاختبار بنجاح"
        });
    });
});

// --- عرض نتائج الاختبارات ---
app.get('/test-results', authenticateToken, (req, res) => {
    const UserID = req.user.id; // بناخده من التوكن لضمان الأمان

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
            // إضافة حقل status: "failed" وتوحيد نمط الاستجابة للأخطاء
            return res.status(500).json({
                status: "failed",
                message: "خطأ في جلب البيانات من قاعدة البيانات"
            });
        }

        // استجابة النجاح بعد إضافة حقل status: "success"
        res.status(200).json({
            status: "success",
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

        // 1. تعديل الاستجابة هنا لتكون JSON لحماية الفرونتيند وإضافة status: "failed"
        if (!message || message.trim() === "") {
            return res.status(400).json({
                status: "failed",
                success: false,
                reply: "الرسالة فارغة، يرجى كتابة شيء ما."
            });
        }

        // تم تنظيف السطر الأخير لتجنب تكرار رسالة المستخدم داخل الـ System Prompt
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
- "Any percentages or scores"

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
- Your main goal is to guide users toward the app's self-assessment feature.

When appropriate, suggest:
- "You can take the Depression self-assessment test in the app to better understand your feelings."
- "There is an Anxiety check in the app that might help you reflect on what you're feeling."

---

6. Crisis Handling:
- If user expresses self-harm or severe distress:
- Respond with immediate empathy
- Encourage reaching out to a trusted person or professional help
- Do NOT leave user alone with instructions or technical suggestions

---

7. Final Objective:
- Help users feel understood, emotionally supported, and gently guided toward the most relevant self-assessment tool in the app.`;

        // إرسال الطلب لـ Groq بشكل منظم وصحيح
        const result = await groq.chat.completions.create({
            model: "llama-3.3-70b-versatile",
            messages: [
                { role: "system", content: systemPrompt },
                { role: "user", content: message } // رسالة المستخدم تمرر هنا فقط بشكل نقي
            ],
            max_tokens: 1024
        });

        const aiText = result.choices[0].message.content;

        // حفظ المحادثة في الداتابيز
        const sql = "INSERT INTO chatMessages (UserID, UserMessage, AiResponse) VALUES (?, ?, ?)";
        db.execute(sql, [UserID, message, aiText], (err) => {
            if (err) {
                console.error("❌ خطأ في حفظ الرسالة في الداتابيز:", err.message);
                // لا نوقف العملية حتى لو فشل الحفظ، نرسل الرد للمستخدم على أي حال
            }

            // استجابة النجاح الموحدة
            res.status(200).json({
                status: "success",
                success: true,
                reply: aiText
            });
        });

    } catch (error) {
        console.error("Groq Error:", error);

        // خطأ الـ Rate Limit تخطي الحد المسموح
        if (error.status === 429) {
            return res.status(503).json({
                status: "failed",
                success: false,
                reply: "الخدمة مشغولة حالياً، برجاء المحاولة بعد قليل 🙏"
            });
        }

        // خطأ السيرفر الداخلي
        res.status(500).json({
            status: "failed",
            success: false,
            reply: "حدث خطأ في التواصل مع الذكاء الاصطناعي"
        });
    }
});

// --- 4. طلب كود إعادة تعيين كلمة المرور (Forgot Password) ---
app.post('/forgot-password', (req, res) => {
    const { Email } = req.body;

    // 1. التحقق من وجود الإيميل في الطلب
    if (!Email) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال البريد الإلكتروني"
        });
    }

    // 2. التأكد أولاً أن الإيميل مسجل في الحسابات الفعالة
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
                message: "هذا البريد الإلكتروني غير مسجل أو غير مفعل"
            });
        }

        // 3. توليد كود الـ OTP
        const resetOtpCode = Math.floor(100000 + Math.random() * 900000).toString();

        // 4. حفظ أو تحديث الكود في الجدول المنفصل (password_resets)
        const sqlInsertReset = "REPLACE INTO password_resets (Email, token_code) VALUES (?, ?)";
        db.execute(sqlInsertReset, [Email, resetOtpCode], (upErr) => {
            if (upErr) {
                return res.status(500).json({
                    status: "failed",
                    message: upErr.message
                });
            }

            // 5. إرسال الإيميل
            const mailOptions = {
                from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                to: Email,
                subject: 'إعادة تعيين كلمة المرور - OTP',
                html: `
                    <div dir="rtl" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e2e8f0; border-radius: 20px; overflow: hidden; background-color: #ffffff;">
                        <div style="background-color: #fef2f2; padding: 35px 20px; text-align: center;">
                            <h1 style="color: #dc2626; margin: 0;">إعادة تعيين كلمة المرور</h1>
                        </div>
                        <div style="padding: 45px 35px; text-align: center;">
                            <p style="color: #475569; font-size: 16px;">كود التحقق الخاص بك (صالح لمدة 10 دقائق):</p>
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
                        message: "فشل في إرسال الإيميل، يرجى المحاولة لاحقاً"
                    });
                }

                // 6. استجابة النجاح الموحدة
                res.status(200).json({
                    status: "success",
                    success: true,
                    message: "تم إرسال كود إعادة التعيين بنجاح.",
                    debug_otp: resetOtpCode
                });
            });
        });
    });
});

// --- 5. الخطوة الثانية: التأكد من الكود والوقت (Verify Reset Code) ---
app.post('/verify-reset-code', (req, res) => {
    const { Email, code } = req.body;

    // 1. التحقق من وجود المدخلات الأساسية
    if (!Email || !code) {
        return res.status(400).json({
            status: "failed",
            message: "برجاء إدخال الإيميل والكود"
        });
    }

    // جلب بيانات الكود من الجدول المنفصل
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
                message: "لم يتم طلب كود لهذا الإيميل أو انتهت صلاحيته"
            });
        }

        const record = results[0];

        // 2. التشييك على الوقت (لو عدى أكتر من 10 دقائق) وتحويل الرد إلى JSON
        if (record.minutes_passed > 10) {
            // نحذفه من جدول الريسيت عشان ننظف أول بأول
            db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);
            return res.status(400).json({
                status: "failed",
                message: "انتهت صلاحية هذا الكود (تعدى 10 دقائق)، يرجى طلب كود جديد"
            });
        }

        // 3. التشييك على صحة الكود وتحويل الرد إلى JSON
        if (record.token_code !== code) {
            return res.status(400).json({
                status: "failed",
                message: "الكود غير صحيح"
            });
        }

        // 4. الكود صح وضمن الـ 10 دقائق ➔ نقوم بتحديث الكود لكلمة 'VERIFIED' كإثبات للخطوة الثالثة
        db.execute("UPDATE password_resets SET token_code = 'VERIFIED' WHERE Email = ?", [Email], (verErr) => {
            if (verErr) {
                return res.status(500).json({
                    status: "failed",
                    message: verErr.message
                });
            }

            // استجابة النجاح الموحدة
            res.status(200).json({
                status: "success",
                success: true,
                message: "تم التحقق من الكود بنجاح. يمكنك الآن تعيين الباسورد الجديد."
            });
        });
    });
});

// --- 6. الخطوة الثالثة والأخيرة: تغيير الباسورد وحذف السجل (تعديل لـ PUT) ---
app.put('/reset-password', async (req, res) => {
    const { Email, password } = req.body;

    // 1. التحقق من اكتمال البيانات المطلوبة
    if (!Email || !password) {
        return res.status(400).json({
            status: "failed",
            message: "البيانات المطلوبة غير مكتملة"
        });
    }

    // 2. التحقق من قوة الباسورد الجديد (مطابقة للـ Regex المحدّث سابقاً شامل الرموز إذا كنت تفضل توحيدها)
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            status: "failed",
            message: "كلمة السر ضعيفة (8 حروف، حرف كبير، حرف صغير، رقم)"
        });
    }

    // 🔍 التشييك أولاً في جدول المستخدمين الرئيسي للتأكد من وجود الإيميل
    const sqlCheckUser = "SELECT * FROM users WHERE Email = ?";
    db.execute(sqlCheckUser, [Email], (userErr, userResults) => {
        if (userErr) {
            return res.status(500).json({
                status: "failed",
                message: userErr.message
            });
        }

        // لو الإيميل مش موجود في الداتابيز أصلاً
        if (userResults.length === 0) {
            return res.status(404).json({
                status: "failed",
                message: "هذا البريد الإلكتروني غير مسجل لدينا، برجاء إنشاء حساب أولاً"
            });
        }

        // لو الحساب موجود، نبدأ نشيك على حالة التفعيل والوقت في جدول password_resets
        const sqlCheckReset = "SELECT *, TIMESTAMPDIFF(MINUTE, CreatedAt, NOW()) AS minutes_passed FROM password_resets WHERE Email = ? AND token_code = 'VERIFIED'";
        db.execute(sqlCheckReset, [Email], async (resetErr, resetResults) => {
            if (resetErr) {
                return res.status(500).json({
                    status: "failed",
                    message: resetErr.message
                });
            }

            // لو الإيميل موجود بس مأكدش الكود في الخطوة التانية، أو الوقت (10 دقائق) انتهى
            if (resetResults.length === 0 || resetResults[0].minutes_passed > 10) {
                // تنظيف الجدول وحذف السجل المنتهي
                db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);
                return res.status(403).json({
                    status: "failed",
                    message: "طلب غير مصرح به أو انتهت صلاحية الـ 10 دقائق، يرجى إعادة المحاولة من الخطوة الأولى"
                });
            }

            try {
                // تشفير الباسورد الجديد
                const hashedPassword = await bcrypt.hash(password, 10);

                // تحديث الباسورد في جدول الـ users
                const sqlUpdateUser = "UPDATE users SET password = ? WHERE Email = ?";
                db.execute(sqlUpdateUser, [hashedPassword, Email], (upErr) => {
                    if (upErr) {
                        return res.status(500).json({
                            status: "failed",
                            message: upErr.message
                        });
                    }

                    // حذف السجل المؤقت من جدول الـ password_resets بعد النجاح
                    db.execute("DELETE FROM password_resets WHERE Email = ?", [Email]);

                    // استجابة النجاح الموحدة
                    res.status(200).json({
                        status: "success",
                        success: true,
                        message: "تم تغيير كلمة المرور بنجاح! يمكنك تسجيل الدخول الآن."
                    });
                });
            } catch (error) {
                res.status(500).json({
                    status: "failed",
                    message: "خطأ في السيرفر أثناء تشفير كلمة المرور"
                });
            }
        });
    });
});

// --- جلب تاريخ الشات للمستخدم الحالي ---
app.get('/chat/history', authenticateToken, (req, res) => {
    const UserID = req.user.id; // بناخده من التوكن لضمان الأمان

    const sql = "SELECT UserMessage, AiResponse, CreatedAt FROM chatMessages WHERE UserID = ? ORDER BY CreatedAt ASC";

    db.execute(sql, [UserID], (err, results) => {
        if (err) {
            console.error("❌ خطأ في جلب تاريخ الشات:", err.message);
            // إضافة حقل status: "failed" وتوحيد نمط الاستجابة للأخطاء
            return res.status(500).json({
                status: "failed",
                message: "فشل في تحميل المحادثات القديمة"
            });
        }

        // استجابة النجاح بعد إضافة حقل status: "success"
        res.status(200).json({
            status: "success",
            success: true,
            history: results // مصفوفة (Array) تحتوي على الرسائل السابقة مرتبة زمنياً تصاعدياً
        });
    });
});


// مبروك مقدماً على التقفيل.. ده الـ Endpoint المطور بالكامل:

app.get('/tests', (req, res) => {
    // 1. تشيك لو في توكن مبعوت في الـ Headers (بدون استخدام middleware إجباري يقفل الريكويست)
    const authHeader = req.headers.authorization;
    let userId = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            // فك التوكن وسحب الـ ID (تأكد من اسم المفتاح عندك جوه التوكن زي UserID أو id)
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
            userId = decoded.UserID || decoded.id; 
        } catch (jwtErr) {
            // لو التوكن بايز أو منتهي الصلاحية، مش هنوقع السيرفر، هنعتبره Visitor عادي
            console.log("ℹ️ Invalid or expired token, treating as guest visitor.");
        }
    }

    let sql = "";
    let queryParams = [];

    // 2. بناء الـ Query بناءً على حالة المستخدم (مسجل ولا زائر)
    if (userId) {
        // 🔥 سيناريو الـ User: بنعمل JOIN وبنعمل تشيك هل اسم الاختبار موجود جوه الـ recommended_tests المكتوبة في الجدول
        sql = `
            SELECT 
                t.TestTypeID, 
                t.TestName, 
                t.Description, 
                t.NormalRange, 
                t.TotalQuestions,
                CASE 
                    WHEN r.recommended_tests IS NOT NULL AND FIND_IN_SET(LOWER(t.TestName), LOWER(r.recommended_tests)) > 0 THEN true
                    ELSE false
                END AS isRecommended
            FROM testtypes t
            LEFT JOIN recommended_tests r ON r.user_id = ?
            ORDER BY isRecommended DESC, t.TestTypeID ASC;
        `;
        queryParams = [userId];
    } else {
        // 🌿 سيناريو الـ Visitor: بنرجع الداتا العادية وكل الاختبارات معاها false
        sql = `
            SELECT 
                TestTypeID, 
                TestName, 
                ` + "Description" + `, 
                NormalRange, 
                TotalQuestions,
                false AS isRecommended
            FROM testtypes
            ORDER BY TestTypeID ASC;
        `;
    }

    // 3. تنفيذ الـ Query المحددة
    db.execute(sql, queryParams, (err, results) => {
        if (err) {
            console.error("❌ خطأ أثناء جلب الاختبارات:", err.message);
            return res.status(500).json({
                status: "failed",
                success: false,
                message: "خطأ في السيرفر عند جلب البيانات"
            });
        }

        // تحويل الـ 1 و 0 اللي طالعين من الـ SQL لـ true و false حقيقيين للفرونتيند
        const formattedResults = results.map(test => ({
            ...test,
            isRecommended: !!test.isRecommended // تحويل لـ Boolean حقيقي
        }));

        // إرجاع النتيجة للفرونت-إند
        res.status(200).json({
            status: "success",
            success: true,
            count: formattedResults.length,
            tests: formattedResults
        });
    });
});

// --- 2. جلب معلومات اختبار معين والأسئلة الخاصة به عن طريق الـ ID ---
app.get('/tests/:testId', (req, res) => {
    const testId = req.params.testId;

    // 1. التأكد إن الـ ID مبعوث وهو عبارة عن رقم
    if (!testId || isNaN(testId)) {
        return res.status(400).json({
            status: "failed",
            success: false,
            message: "معرف الاختبار غير صحيح أو غير موجود"
        });
    }

    // 1️⃣ الاستعلام الأول: جلب بيانات الاختبار نفسه
    const testSql = "SELECT TestTypeID, TestName, Description, NormalRange, TotalQuestions FROM testtypes WHERE TestTypeID = ?";

    db.execute(testSql, [testId], (testErr, testResults) => {
        if (testErr) {
            console.error(`❌ خطأ أثناء جلب بيانات الاختبار رقم ${testId}:`, testErr.message);
            return res.status(500).json({
                status: "failed",
                success: false,
                message: "حدث خطأ في السيرفر أثناء جلب بيانات الاختبار"
            });
        }

        // 2. لو الـ ID مش موجود في جدول الاختبارات أصلاً
        if (testResults.length === 0) {
            return res.status(404).json({
                status: "failed",
                success: false,
                message: "هذا الاختبار غير موجود"
            });
        }

        // حفظ بيانات الاختبار في أوبجكت لوحده
        const testInfo = testResults[0];

        // 2️⃣ الاستعلام الثاني: جلب الأسئلة المربوطة بالاختبار ده
        const questionsSql = "SELECT QuestionID, QuestionText FROM questions WHERE TestTypeID = ? ORDER BY QuestionID ASC";

        db.execute(questionsSql, [testId], (qErr, qResults) => {
            if (qErr) {
                console.error(`❌ خطأ أثناء جلب أسئلة الاختبار رقم ${testId}:`, qErr.message);
                return res.status(500).json({
                    status: "failed",
                    success: false,
                    message: "حدث خطأ في السيرفر أثناء جلب أسئلة الاختبار"
                });
            }

            // 3. إرسال الـ Response بالتقسيمة المطلوبة مضافاً إليها حقل الـ status بنجاح
            res.status(200).json({
                status: "success",
                success: true,
                // أوبجكت يحتوي على معلومات الاختبار بالكامل
                test_details: {
                    id: testInfo.TestTypeID,
                    name: testInfo.TestName,
                    description: testInfo.Description,
                    normal_range: testInfo.NormalRange,
                    total_questions_expected: testInfo.TotalQuestions
                },
                // أوبجكت يحتوي على مصفوفة الأسئلة
                questions_data: {
                    total_questions_found: qResults.length,
                    questions: qResults
                }
            });
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// ... نهاية الكود بتاعك
module.exports = app;