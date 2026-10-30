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
// Bài làm cá nhân (không có nhóm BTL — xem header báo cáo "Nhóm BTL (nếu có)").
// Vì vậy các tài khoản user-manager/auditor/member/tro-giang dưới đây là dữ liệu
// DEMO tự đặt (không phải người thật), chỉ để minh họa hệ thống RBAC hoạt động
// với nhiều người dùng — không phải thành viên nhóm/bạn học thật. Ghi rõ điều
// này trong báo cáo (mục "Nhóm BTL" / mục 2.1 nếu được hỏi) để trung thực.
const USERS = [
  {
    email: "tuan.ph261019m@sis.hust.edu.vn",
    fullName: "Phạm Hải Tuấn",
    phone: null,
    password: "Admin@2026",
    roles: ["super-admin"],
  },
  {
    email: "minh.khoi.demo@sis.hust.edu.vn",
    fullName: "Lê Minh Khôi",
    phone: null,
    password: "Member@2026",
    roles: ["user-manager"],
  },
  {
    email: "hong.nhung.demo@sis.hust.edu.vn",
    fullName: "Trần Thị Hồng Nhung",
    phone: null,
    password: "Member@2026",
    roles: ["auditor"],
  },
  {
    email: "gia.bao.demo@sis.hust.edu.vn",
    fullName: "Đỗ Gia Bảo",
    phone: null,
    password: "Member@2026",
    roles: ["member"],
  },
  {
    email: "lan.anh.demo@sis.hust.edu.vn",
    fullName: "Nguyễn Thị Lan Anh",
    phone: null,
    password: "Member@2026",
    roles: ["member"],
  },
  // 1 người được gán vai trò tự tạo "tro-giang" (yêu cầu mục 1.11)
  {
    email: "duc.anh.demo@sis.hust.edu.vn",
    fullName: "Vũ Đức Anh",
    phone: null,
    password: "Member@2026",
    roles: ["tro-giang"],
  },
];

// ====== Tài khoản riêng cho giảng viên kiểm tra (mục 1.2) ======
// Tách biệt hoàn toàn với tài khoản demo ở trên — không dùng mật khẩu cá nhân,
// không xóa/khóa/đổi mật khẩu các tài khoản này cho đến khi có điểm.
const GRADER_USERS = [
  {
    email: "gv.admin@sis.hust.edu.vn",
    fullName: "Giảng viên - Quản trị viên tối cao",
    phone: null,
    password: "Grader@2026",
    roles: ["super-admin"],
  },
  {
    email: "gv.manager@sis.hust.edu.vn",
    fullName: "Giảng viên - Quản lý người dùng",
    phone: null,
    password: "Grader@2026",
    roles: ["user-manager"],
  },
  {
    email: "gv.auditor@sis.hust.edu.vn",
    fullName: "Giảng viên - Kiểm toán viên",
    phone: null,
    password: "Grader@2026",
    roles: ["auditor"],
  },
  {
    email: "gv.member@sis.hust.edu.vn",
    fullName: "Giảng viên - Thành viên",
    phone: null,
    password: "Grader@2026",
    roles: ["member"],
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

  const allUsers = [...USERS, ...GRADER_USERS];
  for (const u of allUsers) {
    await User.create({
      email: u.email,
      fullName: u.fullName,
      phone: u.phone ?? null,
      passwordHash: await bcrypt.hash(u.password, 10),
      roles: u.roles.map((code) => roleId[code]),
    });
  }

  console.log(
    `Đã tạo ${PERMISSIONS.length} quyền, ${roles.length} vai trò, ${allUsers.length} người dùng.`,
  );
  await mongoose.disconnect();
})();
