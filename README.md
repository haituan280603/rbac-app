# rbac-app — Ex3 Fullstack RBAC (Quản lý người dùng & phân quyền)

Bài tập IT4409 — Backend Node.js/Express/MongoDB + Frontend React (CDN), theo đúng đặc tả
"BÀI TẬP FULLSTACK – QUẢN LÝ NGƯỜI DÙNG VÀ PHÂN QUYỀN RBAC".

## Cấu trúc

```
rbac-app/
├── backend/        Express API (xem backend/.env.example để biết biến môi trường cần có)
├── frontend/        index.html — React qua CDN, không cần build
└── postman/        RBAC.postman_collection.json — T01-T24
```

## Chạy ở local

### 1. Backend

```bash
cd backend
npm install
cp .env.example .env   # rồi điền MONGODB_URI thật (MongoDB Atlas) + JWT_SECRET
npm run seed            # tạo permission/role/user mẫu — ĐỌC KỸ seed.js trước khi chạy,
                         # có 4-5 dòng đánh dấu TODO cần thay bằng tên/email THẬT của
                         # thành viên nhóm BTL và các bạn ngồi xung quanh (đề bài yêu cầu
                         # dữ liệu chính xác, không được seed bằng placeholder khi nộp bài)
npm start                # http://localhost:3001
```

### 2. Frontend

Mở `frontend/index.html` bằng **VS Code Live Server** (`http://127.0.0.1:5500`), **không** mở
trực tiếp bằng `file://` — origin `null` sẽ bị CORS chặn (backend chỉ cho phép origin nằm trong
`CORS_ORIGINS`).

### 3. Postman

Import `postman/RBAC.postman_collection.json`, đổi biến collection `baseUrl` nếu cần, chạy bằng
**Collection Runner** theo thứ tự: folder `0. Setup` trước, rồi `T01-T24`.

## Tài khoản mẫu sau khi seed (đổi mật khẩu thật trước khi đưa cho giảng viên)

| Vai trò      | Email (ví dụ, xem seed.js)           | Mật khẩu    |
| ------------ | ------------------------------------ | ----------- |
| super-admin  | 20261019m@sis.hust.edu.vn            | Admin@2026  |
| user-manager | thanhvien1@sis.hust.edu.vn (TODO)    | Member@2026 |
| auditor      | thanhvien2@sis.hust.edu.vn (TODO)    | Member@2026 |
| member       | banxungquanh1@sis.hust.edu.vn (TODO) | Member@2026 |

## Triển khai online (gợi ý — bạn tự thực hiện, cần tài khoản cá nhân của bạn)

Đề bài yêu cầu một bản "triển khai online" thật (có URL công khai) — **đẩy code lên GitHub KHÔNG
đồng nghĩa với việc ứng dụng đang chạy**: GitHub chỉ lưu mã nguồn, không tự chạy server Node.js
hay MongoDB của bạn. Cần 2-3 dịch vụ hosting riêng (đều có gói miễn phí, nhưng đều cần bạn tự
đăng ký bằng tài khoản cá nhân):

1. **MongoDB Atlas** (https://cloud.mongodb.com) — tạo cluster free (M0), tạo database user
   (username/password theo đúng MSSV như `.env.example` ghi), vào **Network Access** → thêm
   `0.0.0.0/0` (hoặc dải IP của host Backend) để Backend trên host kết nối được. Copy connection
   string vào biến môi trường `MONGODB_URI` trên host Backend (bước 2).
2. **Render** (https://render.com) hoặc Railway/Fly.io — tạo **Web Service** mới trỏ tới thư mục
   `backend/` của repo GitHub này, build command `npm install`, start command `npm start`, khai
   báo đủ 4 biến môi trường (`MONGODB_URI`, `JWT_SECRET`, `ACCESS_TOKEN_TTL`, `CORS_ORIGINS` — nhớ
   thêm đúng origin Frontend thật vào `CORS_ORIGINS` sau khi có URL ở bước 3). Sau khi deploy xong
   sẽ có 1 URL dạng `https://<ten>.onrender.com`; `Base URL` của API là
   `https://<ten>.onrender.com/api/v1`.
3. **Netlify / Vercel / GitHub Pages** cho `frontend/index.html` (file tĩnh, không cần build) —
   hoặc đơn giản nhất: phục vụ luôn file này từ chính Backend (thêm
   `app.use(express.static("../frontend"))` vào `server.js` nếu muốn gộp chung 1 host, tự cân
   nhắc và ghi vào mục 4.2 "Khác biệt so với đề bài" của báo cáo nếu làm khác mặc định).
4. Trong `frontend/index.html`, đổi hằng `API_BASE` sang đúng Base URL thật ở bước 2 trước khi
   deploy Frontend.

Ghi lại đúng các bước bạn thực sự làm (có thể khác hướng dẫn trên) vào mục 5.3 của báo cáo —
giảng viên yêu cầu mô tả đủ chi tiết để người khác làm lại được.

## Lưu ý bảo mật

- `.env` **không** được commit (đã có trong `.gitignore`).
- Token JWT chỉ chứa `sub` (id người dùng), không chứa danh sách quyền — quyền luôn được tra lại
  từ CSDL ở mỗi request (xem `backend/middleware/auth.js`).
