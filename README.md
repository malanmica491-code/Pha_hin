# กระดานสนทนา นศท. — วางขึ้น Netlify

โครงสร้าง
- `public/index.html`  หน้าเว็บทั้งหมด
- `netlify/functions/api.mjs`  หลังบ้าน (ใช้ Netlify Blobs เก็บข้อมูล ไม่ต้องตั้งค่าฐานข้อมูล)
- `netlify.toml`, `package.json`

ขั้นตอน (ต้องใช้ Git หรือ Netlify CLI เพราะมี Functions และ npm package)
1. อัปโหลดโฟลเดอร์นี้ทั้งหมดขึ้น GitHub (repo ใหม่) แล้วใน Netlify เลือก Add new site → Import from Git
   (หรือติดตั้ง Netlify CLI แล้วรัน `netlify deploy --prod` ในโฟลเดอร์นี้)
2. Site configuration → Environment variables → เพิ่ม `ADMIN_CODE` = รหัสลับที่คุณตั้งเอง (ใช้ครั้งเดียวตอนสร้างผู้ดูแลคนแรก)
3. Deploy ใหม่ แล้วเปิดเว็บ → กด "สร้างบัญชีใหม่" บัญชีแรกจะมีช่องใส่ ADMIN_CODE และจะได้เป็นผู้ดูแล
4. คนอื่นสมัครตามปกติ (เป็นสมาชิกทั่วไป)
