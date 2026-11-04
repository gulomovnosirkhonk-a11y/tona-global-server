TONA 0.2 — ishga tushirish

Python 3.12. pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

Render: Docker runtime, health check /healthz, bitta instance.
Doimiy disk: /data. TONA_DATA_DIR=/data.
Diskli hosting pullik; bepul vaqtinchalik diskda akkauntlar yo‘qolishi mumkin.

Email kodlari: SMTP_HOST, SMTP_PORT (587), SMTP_FROM, SMTP_USER, SMTP_PASSWORD.
SMS kodlari: Twilio Verify loyihasining TWILIO_ACCOUNT_SID,
TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID qiymatlari.
Sirlarni faqat Render Environment oynasida kiriting, GitHub’ga yuklamang.
Hozir TONA_REQUIRE_VERIFICATION=false: telefon/email + parol bilan ro‘yxatdan o‘tiladi.
Telefon/email egaligi tasdiqlanmaydi; kontaktlar username orqali ikki tomon roziligi bilan qo‘shiladi.
Provayderlar ulangach TONA_REQUIRE_VERIFICATION=true qilib yangi akkauntlar uchun kodni yoqing.
Avvalgi bazadagi akkauntlar avtomatik qayta tasdiqlanmaydi.

Kontaktlar ikki tomon roziligi bilan qo‘shiladi. Reels va stories faqat
muallif va uning tasdiqlangan kontaktlariga ochiladi. Kontakt o‘chirilsa,
server yangi kirishni rad etadi; allaqachon yuklab olingan nusxani qaytarib bo‘lmaydi.

Sinov: pip install pytest httpx; python -m pytest test_app.py -q
Testlar uch akkaunt, xabarlar, WebSocket, media ruxsatlari, kontaktni o‘chirish,
postni o‘chirish, noto‘g‘ri kod va logoutni tekshiradi. SMS/email provayderlari
haqiqiy xizmat bilan sinovdan o‘tkazilmadi.

Cheklovlar: bu boshlang‘ich chat versiyasi; audio/videoqo‘ng‘iroqlar, guruhlar,
end-to-end shifrlash, parolni tiklash va katta yuklama uchun ko‘p serverli
arxitektura hali yo‘q. Ommaviy chiqarishdan avval provayder, backup va
haqiqiy ikki qurilmadagi sinovlarni yakunlang.
