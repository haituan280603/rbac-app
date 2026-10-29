require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const Permission = require("./models/Permission");
const Role = require("./models/Role");
const User = require("./models/User");

const PERMISSIONS = [
  ["users:read", "Xem danh sách và chi tiết người dùng"],
  ["users:create", "Tạo người dùng"],
  ["users:update", "Sửa thông tin, khóa/mở khóa người dùng"],
  ["users:delete", "Xóa người dùng"],
  ["roles:read", "Xem vai trò và quyền của vai trò"],
  ["roles:create", "Tạo vai trò"],
  ["roles:update", "Sửa vai trò, thay bộ quyền của vai trò"],
  ["roles:delete", "Xóa vai trò"],
  ["roles:assign", "Gán / gỡ vai trò cho người dùng"],
  ["permissions:read", "Xem danh mục quyền"],
].map(([code, description]) => ({
  code,
  resource: code.split(":")[0],
  action: code.split(":")[1],
  description,
}));

const ALL = PERMISSIONS.map((p) => p.code);

// Ma trận quyền đúng theo mục II.1.5 của đề bài
const ROLES = [
  {
    code: "super-admin",
    name: "Quản trị viên tối cao",
    isSystem: true,
    permissions: ALL,
  },
  {
    code: "user-manager",
    name: "Quản lý người dùng",
    isSystem: true,
    permissions: [
      "users:read",
      "users:create",
      "users:update",
      "roles:read",
      "roles:assign",
      "permissions:read",
    ],
  },
  {
    code: "auditor",
    name: "Kiểm toán viên",
    isSystem: true,
    permissions: ["users:read", "roles:read", "permissions:read"],
  },
  { code: "member", name: "Thành viên", isSystem: true, permissions: [] },
  // Vai trò tự tạo (không phải hệ thống) — theo yêu cầu mục 1.11
  {
    code: "tro-giang",
    name: "Trợ giảng",
    isSystem: false,
    description: "Hỗ trợ xem danh sách người dùng và vai trò",
    permissions: ["users:read", "roles:read"],
  },
];

// ====== Dữ liệu tối thiểu theo mục III.1.11 ======
// LƯU Ý: các dòng đánh dấu TODO là chỗ-giữ-chỗ (placeholder) — PHẢI thay bằng
// họ tên/email THẬT của thành viên nhóm BTL và các bạn ngồi xung quanh trước
// khi seed dữ liệu thật lên MongoDB Atlas để nộp bài (đề bài yêu cầu "chính
// xác họ tên, email" — không được seed bằng placeholder khi nộp).
const USERS = [
  {
    email: "20261019m@sis.hust.edu.vn",
    fullName: "Phạm Hải Tuấn",
    phone: null,
    password: "Admin@2026",
    roles: ["super-admin"],
  },
  // TODO: thay bằng thành viên nhóm BTL thật (vai trò user-manager)
  {
    email: "thanhvien1@sis.hust.edu.vn",
    fullName: "Thành viên nhóm 1 (TODO: thay tên thật)",
    phone: null,
    password: "Member@2026",
    roles: ["user-manager"],
  },
  // TODO: thay bằng thành viên nhóm BTL thật (vai trò auditor)
  {
    email: "thanhvien2@sis.hust.edu.vn",
    fullName: "Thành viên nhóm 2 (TODO: thay tên thật)",
    phone: null,
    password: "Member@2026",
    roles: ["auditor"],
  },
  // TODO: thay bằng tên các bạn ngồi xung quanh thật (vai trò member)
  {
    email: "banxungquanh1@sis.hust.edu.vn",
    fullName: "Bạn xung quanh 1 (TODO: thay tên thật)",
    phone: null,
    password: "Member@2026",
    roles: ["member"],
  },
  {
    email: "banxungquanh2@sis.hust.edu.vn",
    fullName: "Bạn xung quanh 2 (TODO: thay tên thật)",
    phone: null,
    password: "Member@2026",
    roles: ["member"],
  },
  // 1 người được gán vai trò tự tạo "tro-giang" (yêu cầu mục 1.11)
  {
    email: "trogiang1@sis.hust.edu.vn",
    fullName: "Trợ giảng mẫu (TODO: thay tên thật nếu cần)",
    phone: null,
    password: "Member@2026",
    roles: ["tro-giang"],
  },
];

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  await Promise.all([
    Permission.deleteMany({}),
    Role.deleteMany({}),
    User.deleteMany({}),
  ]);
  await Promise.all([Permission.init(), Role.init(), User.init()]); // tạo unique index

  await Permission.insertMany(PERMISSIONS);
  const roles = await Role.insertMany(ROLES);
  const roleId = Object.fromEntries(roles.map((r) => [r.code, r._id]));

  for (const u of USERS) {
    await User.create({
      email: u.email,
      fullName: u.fullName,
      phone: u.phone ?? null,
      passwordHash: await bcrypt.hash(u.password, 10),
      roles: u.roles.map((code) => roleId[code]),
    });
  }

  console.log(
    `Đã tạo ${PERMISSIONS.length} quyền, ${roles.length} vai trò, ${USERS.length} người dùng.`,
  );
  await mongoose.disconnect();
})();
