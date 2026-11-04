TONA 0.3 — profil, hikoyalar, maxfiylik va moderatsiya

Ishga tushirish:
Python 3.12; pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

Hozir Render FREE, Docker, bitta instance. Health check: /healthz.
TONA_EPHEMERAL=true. Doimiy disk yo‘q. Qayta deploy/restartda ma’lumotlar
va administrator huquqi ham yo‘qolishi mumkin. render.yaml bepul tarifni ishlatadi.
Ommaviy, doimiy xizmat uchun tashqi doimiy baza, media saqlash va backup kerak.

Profil rasmi (5 MB), display name, bio (160 belgi), rasm maxfiyligi,
qidiruvdan yashirish, yangi kontakt so‘rovlarini yopish, light/dark rejim,
xabar shrift o‘lchami, faol qurilmalar, boshqa seanslarni tugatish,
parol almashtirish, kontaktlarni bloklash, 24 soatlik hikoya va reels ishlaydi.

Xavfsizlik: HttpOnly/SameSite sessiya cookie, HTTPS ostida Secure cookie,
CSRF origin/header tekshiruvi, strict CSP, PBKDF2-SHA256 600000 iteratsiya
(eski parollar bilan moslik saqlangan), yuklama/urinish limitlari, rasmni
qayta kodlash va EXIF/GPS metama’lumotlarini tashlash. Video sarlavhasi
tekshiriladi, ammo professional zararli fayl skaneri ulanmagan.

Moderatsiya:
Spam, firibgarlik, tazyiq, zo‘ravonlik, ekstremizm va bolalar xavfsizligi
bo‘yicha shikoyatlar. Faqat shikoyatga tegishli profil/post/xabar nusxasi
navbatga olinadi. Moderator postni yashirishi, akkauntni cheklashi yoki
shikoyatni yopishi mumkin. Amallar jurnalga yoziladi.

Ega akkaunti: @nosirkhon. Username o‘zi administrator huquqini bermaydi.
1. Render Environment’da TONA_OWNER_USERNAME=nosirkhon saqlansin.
2. TONA_OWNER_KEY uchun kamida 32 belgili tasodifiy maxfiy kalitni egasi o‘zi kiritsin.
3. @nosirkhon akkauntida Sozlamalar > Xavfsizlik > Egasi boshqaruvini
   faollashtirish tugmasiga bosib, shu kalitni kiritsin.
Kalitni GitHub’ga, ommaviy faylga yoki boshqa odamlarga bermang.
Kalit ulanmaguncha moderator tayinlanmaydi; shikoyatlar faqat saqlanadi.
Baza reset bo‘lsa, egasi o‘z akkauntida shu kalit bilan huquqni qayta oladi.

Telefon/email + parol rejimi tanlangan; egalik hali tasdiqlanmaydi.
SMS/email keyinchalik: TONA_REQUIRE_VERIFICATION=true, SMTP_HOST,
SMTP_PORT=587, SMTP_FROM, SMTP_USER, SMTP_PASSWORD va Twilio Verify uchun
TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID.

Sinov: pip install pytest httpx; python -m pytest test_app.py -q
7 ta integratsion test: chat, media ruxsatlari, profil, cookie/CSRF,
seanslar, parol, bloklash, hikoya muddati va moderatsiya.
Mahalliy demo akkauntlari deploy paketiga kiritilmagan.

Cheklovlar: end-to-end shifrlash, audio/videoqo‘ng‘iroqlar, guruhlar,
avtomatik terrorizm/jinoyat aniqlash, doimiy navbatchi moderatsiya, parolni
unutganda tiklash, store ilovalari va professional audit hali yo‘q.
Noqonuniy faoliyatning butunlay bo‘lmasligi kafolatlanmaydi.
