require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());

// --- إعدادات الاتصال بـ Aiven ---
const db = mysql.createPool({
    host: 'safe-space-saffe-space.j.aivencloud.com',
    port: 10399,
    user: 'avnadmin',
    password: process.env.DB_PASSWORD, // استخدم الباسورد الخاص بك هنا
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
    const token = authHeader && authHeader.split(' ')[1]; // Authorization: Bearer TOKEN

    if (!token) return res.status(401).send("يجب تسجيل الدخول أولاً");

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.status(403).send("التوكن غير صالح أو انتهى");
        req.user = user; // هنا بنخزن بيانات اليوزر اللي جاية من التوكن (الـ id)
        next();
    });
};

// --- إعداد مرسل الإيميلات (OTP) ---
// ملاحظة: لعمل هذا الجزء بشكل فعلي، يجب استخدام إيميل حقيقي وباسورد تطبيقات (App Password)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // true لـ port 465، false لـ ports تانية
    auth: {
        user: 'mental.health.auth@gmail.com',
        pass: process.env.EMAIL_PASS // الـ 16 حرف بتوع الـ App Password
    }
});

// --- 1. تسجيل حساب جديد (Register) ---
app.post('/register', async (req, res) => {
    const {
        FullName, Email,
        password,
        Phone, Gender, DateOfBirth
    } = req.body;

    // B. التحققات (Regex)
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
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString(); // كود عشوائي

        // ملاحظة: تأكد من وجود أعمدة verification_code و is_verified في جدولك
        const sql = `INSERT INTO users (FullName, Email, password, Phone, Gender, DateOfBirth, verification_code, is_verified) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, 0)`;

        db.execute(sql, [FullName, Email, hashedPassword, Phone, Gender.toLowerCase(), DateOfBirth, otpCode], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') return res.status(400).send("الايميل موجود بالفعل");
                return res.status(500).send(err.message);
            }

            // تجهيز رسالة الإيميل
            const mailOptions = {
                from: '"Mental Health Support" <mental.health.auth@gmail.com>',
                to: Email,
                subject: 'كود تفعيل حسابك - OTP',
                text: `أهلاً بك، كود التفعيل الخاص بك هو: ${otpCode}`,
                html: `<b>أهلاً بك،</b><br>كود التفعيل الخاص بك هو: <h2 style="color:blue;">${otpCode}</h2>`
            };

            // تنفيذ الإرسال فعلياً
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error("❌ فشل إرسال الإيميل:", error.message);
                    // بنبعت رد للمستخدم حتى لو الإيميل فشل عشان نعرفه إن الحساب اتعمل بس الكود مبعتش
                    return res.status(201).json({
                        message: "تم إنشاء الحساب، ولكن فشل إرسال كود التفعيل.",
                        error: error.message
                    });
                }

                console.log("✅ تم إرسال الإيميل بنجاح:", info.response);
                res.status(201).json({
                    message: "تم إنشاء الحساب بنجاح. برجاء فحص إيميلك لتفعيل الحساب.",
                    debug_otp: otpCode // ده للتجربة فقط في البداية
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

        // التأكد من التفعيل
        if (user.is_verified === 0) return res.status(403).send("برجاء تفعيل الحساب أولاً");

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send("كلمة السر خطأ");

        const token = jwt.sign({ id: user.UserID }, 'secret_key', { expiresIn: '1h' });

        res.json({
            message: "تم تسجيل الدخول بنجاح",
            token: token,
            user: { id: user.UserID, name: user.FullName }
        });
    });
});


// --- عرض قائمة الأطباء (Get All Doctors) ---
app.get('/doctors', (req, res) => {
    // استعلام لجلب جميع الأطباء وترتيبهم حسب الأحدث
    const sql = "SELECT * FROM doctors ORDER BY CreatedAt DESC";

    db.execute(sql, (err, results) => {
        if (err) {
            console.error("❌ خطأ في جلب بيانات الأطباء:", err.message);
            return res.status(500).send("خطأ في السيرفر عند جلب البيانات");
        }

        // إرسال البيانات في شكل JSON
        res.status(200).json({
            success: true,
            count: results.length,
            data: results
        });
    });
});

// --- عرض طبيب واحد محدد بواسطة الـ ID ---
app.get('/doctors/:id', (req, res) => {
    const doctorId = req.params.id;
    const sql = "SELECT * FROM doctors WHERE DoctorID = ?";

    db.execute(sql, [doctorId], (err, results) => {
        if (err) return res.status(500).send(err.message);
        if (results.length === 0) return res.status(404).send("الطبيب غير موجود");

        res.status(200).json(results[0]);
    });
});


// --- إضافة نتيجة اختبار جديد (Add Test Result) ---
app.post('/test-results', authenticateToken, (req, res) => {
    const { TestTypeID, ResultValue } = req.body;
    const UserID = req.user.id; // جبناه من التوكن آلياً

    const sql = "INSERT INTO testresults (UserID, TestTypeID, ResultValue) VALUES (?, ?, ?)";
    
    db.execute(sql, [UserID, TestTypeID, ResultValue], (err, result) => {
        if (err) return res.status(500).send(err.message);
        res.status(201).json({ message: "تم إضافة نتيجة الاختبار بنجاح" });
    });
});

// --- عرض نتائج الاختبارات الخاصة بالمستخدم مع اسم الاختبار (Get My Test Results with Names) ---
app.get('/test-results', authenticateToken, (req, res) => {
    const UserID = req.user.id; // جبناه من التوكن

    // استخدمنا JOIN لربط الجدولين عن طريق TestTypeID
    const sql = `
        SELECT 
            tr.TestResultID, 
            tr.ResultValue, 
            tr.ResultDate, 
            tt.TestName, 
            tt.Unit, 
            tt.NormalRange
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// ... نهاية الكود بتاعك
module.exports = app;