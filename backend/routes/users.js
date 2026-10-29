const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Role = require("../models/Role");
const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions, isLastSuperAdmin } = require("../utils/rbac");
const {
  fail,
  detail,
  notAllowedFields,
  isObjectId,
  parsePaging,
  parseSort,
  escapeRegex,
  pageMeta,
  userView,
  roleSummary,
} = require("../utils/http");

const router = express.Router();
router.use(authenticate); // mọi endpoint dưới đây đều cần đăng nhập

const PASSWORD_RE = /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

// Middleware nạp user theo :userId (bỏ qua user đã xóa mềm)
async function loadUser(req, res, next) {
  const { userId } = req.params;
  const user = isObjectId(userId)
    ? await User.findOne({
        _id: userId,
        status: { $ne: "deleted" },
      }).populate("roles")
    : null;
  if (!user)
    return fail(res, 404, "USER_NOT_FOUND", "Không tìm thấy người dùng.");
  req.target = user;
  next();
}

// Middleware nạp role theo :roleId
async function loadRole(req, res, next) {
  const { roleId } = req.params;
  const role = isObjectId(roleId) ? await Role.findById(roleId) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy vai trò.");
  req.role = role;
  next();
}

// ============ U1: GET /users ============
router.get("/", requirePermission("users:read"), async (req, res) => {
  const q = req.query;
  const details = [];
  const { page, limit } = parsePaging(q, details);
  const sort = parseSort(
    q.sort || "-createdAt",
    ["fullName", "email", "createdAt", "lastLoginAt"],
    details,
  );
  if (q.status && !["active", "locked"].includes(q.status))
    details.push(
      detail("status", "INVALID_VALUE", "status phải là active hoặc locked."),
    );
  if (q.roleId !== undefined && !isObjectId(q.roleId))
    details.push(
      detail("roleId", "INVALID_VALUE", "roleId phải là ObjectId hợp lệ."),
    );
  if (q.q !== undefined && String(q.q).trim().length < 2)
    details.push(detail("q", "TOO_SHORT", "q phải có tối thiểu 2 ký tự."));
  if (details.length)
    return fail(
      res,
      400,
      "INVALID_QUERY_PARAMETER",
      "Tham số truy vấn không hợp lệ.",
      details,
    );

  const filter = { status: q.status || { $ne: "deleted" } };
  if (q.roleId) filter.roles = q.roleId; // mảng chứa phần tử roleId
  if (q.q) {
    const re = { $regex: escapeRegex(String(q.q).trim()), $options: "i" };
    filter.$or = [{ fullName: re }, { email: re }];
  }

  const [items, totalItems] = await Promise.all([
    User.find(filter)
      .sort({ ...sort, _id: 1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate("roles"),
    User.countDocuments(filter),
  ]);
  res.json({
    data: items.map(userView),
    meta: pageMeta(page, limit, totalItems),
  });
});

// ============ U2: POST /users ============
router.post("/", requirePermission("users:create"), async (req, res) => {
  const body = req.body || {};
  const details = notAllowedFields(body, [
    "email",
    "fullName",
    "phone",
    "password",
    "roleIds",
  ]);
  if (!body.email) details.push(detail("email", "REQUIRED", "Thiếu email."));
  if (!body.fullName)
    details.push(detail("fullName", "REQUIRED", "Thiếu họ tên."));
  if (!body.password)
    details.push(
      detail("password", "REQUIRED", "Mật khẩu không được để trống."),
    );
  else if (!PASSWORD_RE.test(body.password))
    details.push(
      detail(
        "password",
        "WEAK_PASSWORD",
        "Mật khẩu tối thiểu 8 ký tự, có chữ hoa, chữ số và ký tự đặc biệt.",
      ),
    );
  if (
    body.roleIds !== undefined &&
    (!Array.isArray(body.roleIds) || !body.roleIds.every(isObjectId))
  )
    details.push(
      detail(
        "roleIds",
        "INVALID_VALUE",
        "roleIds phải là mảng ObjectId hợp lệ.",
      ),
    );
  if (details.length)
    return fail(
      res,
      400,
      "VALIDATION_ERROR",
      "Dữ liệu đầu vào không hợp lệ.",
      details,
    );

  // Vai trò: có roleIds -> cần roles:assign, mọi role phải tồn tại, không vượt quyền người gọi
  let roles = [];
  const roleIds = [...new Set(body.roleIds || [])];
  if (roleIds.length) {
    if (!req.permissions.has("roles:assign"))
      return fail(
        res,
        403,
        "FORBIDDEN",
        "Gán vai trò khi tạo người dùng cần quyền roles:assign.",
      );
    roles = await Role.find({ _id: { $in: roleIds } });
    if (roles.length !== roleIds.length)
      return fail(
        res,
        400,
        "ROLE_NOT_FOUND",
        "Có vai trò không tồn tại trong roleIds.",
      );
    const allPerms = [...new Set(roles.flatMap((r) => r.permissions))];
    const missing = missingPermissions(allPerms, req.permissions);
    if (missing.length)
      return fail(
        res,
        403,
        "PRIVILEGE_ESCALATION",
        `Không thể gán vai trò có quyền bạn không có: ${missing.join(", ")}.`,
      );
  } else {
    roles = await Role.find({ code: "member" }); // mặc định
  }

  if (await User.exists({ email: String(body.email).trim().toLowerCase() }))
    return fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.");

  const user = await User.create({
    email: body.email,
    fullName: body.fullName,
    phone: body.phone ?? null,
    passwordHash: await bcrypt.hash(body.password, 10),
    roles: roles.map((r) => r._id),
  });
  await user.populate("roles");
  res.status(201).location(`${req.baseUrl}/${user._id}`).json(userView(user));
});

// ============ U3: GET /users/:userId ============
router.get("/:userId", requirePermission("users:read"), loadUser, (req, res) =>
  res.json(userView(req.target)),
);

// ============ U4: PATCH /users/:userId ============
router.patch(
  "/:userId",
  requirePermission("users:update"),
  loadUser,
  async (req, res) => {
    const body = req.body || {};
    const allowed = ["fullName", "phone", "email", "status"];
    const details = notAllowedFields(body, allowed);

    if ("status" in body && !["active", "locked"].includes(body.status))
      details.push(
        detail("status", "INVALID_VALUE", "status phải là active hoặc locked."),
      );
    if ("fullName" in body) {
      const v = String(body.fullName || "").trim();
      if (v.length < 2 || v.length > 100)
        details.push(
          detail("fullName", "INVALID_VALUE", "Họ tên phải có 2-100 ký tự."),
        );
    }
    if ("email" in body && !/^\S+@\S+\.\S+$/.test(String(body.email || "")))
      details.push(
        detail("email", "INVALID_VALUE", "Email không đúng định dạng."),
      );
    if (
      "phone" in body &&
      body.phone &&
      !/^\+[1-9]\d{7,14}$/.test(String(body.phone))
    )
      details.push(
        detail(
          "phone",
          "INVALID_VALUE",
          "Số điện thoại theo định dạng E.164, ví dụ +84912345678.",
        ),
      );
    if (details.length)
      return fail(
        res,
        400,
        "VALIDATION_ERROR",
        "Dữ liệu đầu vào không hợp lệ.",
        details,
      );

    const isSelf = String(req.target._id) === String(req.user._id);

    if ("status" in body && body.status === "locked") {
      if (isSelf)
        return fail(
          res,
          403,
          "SELF_ACTION_FORBIDDEN",
          "Bạn không thể tự khóa chính mình.",
        );
      if (await isLastSuperAdmin(req.target))
        return fail(
          res,
          409,
          "LAST_SUPER_ADMIN",
          "Không thể khóa super-admin active cuối cùng.",
        );
    }

    if ("email" in body) {
      const newEmail = String(body.email).trim().toLowerCase();
      if (
        newEmail !== req.target.email &&
        (await User.exists({ email: newEmail }))
      )
        return fail(res, 409, "EMAIL_ALREADY_EXISTS", "Email đã được sử dụng.");
    }

    for (const k of allowed) {
      if (k in body) {
        req.target[k] =
          k === "email"
            ? String(body.email).trim().toLowerCase()
            : k === "phone"
              ? body.phone || null
              : k === "fullName"
                ? String(body.fullName).trim()
                : body[k];
      }
    }
    await req.target.save();
    await req.target.populate("roles");
    res.json(userView(req.target));
  },
);

// ============ U5: DELETE /users/:userId (xóa mềm) ============
router.delete(
  "/:userId",
  requirePermission("users:delete"),
  loadUser,
  async (req, res) => {
    const isSelf = String(req.target._id) === String(req.user._id);
    if (isSelf)
      return fail(
        res,
        403,
        "SELF_ACTION_FORBIDDEN",
        "Bạn không thể tự xóa chính mình.",
      );
    if (await isLastSuperAdmin(req.target))
      return fail(
        res,
        409,
        "LAST_SUPER_ADMIN",
        "Không thể xóa super-admin active cuối cùng.",
      );
    req.target.status = "deleted";
    await req.target.save();
    res.status(204).end();
  },
);

// ============ UR1: GET /users/:userId/roles ============
router.get(
  "/:userId/roles",
  requirePermission("users:read"),
  loadUser,
  (req, res) => {
    const data = req.target.roles.filter((r) => r && r.code).map(roleSummary);
    res.json({ data, meta: { totalItems: data.length } });
  },
);

// ============ UR2: PUT /users/:userId/roles/:roleId (idempotent) ============
router.put(
  "/:userId/roles/:roleId",
  requirePermission("roles:assign"),
  loadUser,
  loadRole,
  async (req, res) => {
    const missing = missingPermissions(req.role.permissions, req.permissions);
    if (missing.length)
      return fail(
        res,
        403,
        "PRIVILEGE_ESCALATION",
        `Không thể gán vai trò '${req.role.code}' vì bạn không có quyền: ${missing.join(", ")}.`,
      );
    await User.updateOne(
      { _id: req.target._id },
      { $addToSet: { roles: req.role._id } },
    );
    res.status(204).end();
  },
);

// ============ UR3: DELETE /users/:userId/roles/:roleId (idempotent) ============
router.delete(
  "/:userId/roles/:roleId",
  requirePermission("roles:assign"),
  loadUser,
  loadRole,
  async (req, res) => {
    const isSelf = String(req.target._id) === String(req.user._id);
    if (isSelf)
      return fail(
        res,
        403,
        "SELF_ACTION_FORBIDDEN",
        "Bạn không thể tự gỡ vai trò của chính mình.",
      );
    const missing = missingPermissions(req.role.permissions, req.permissions);
    if (missing.length)
      return fail(
        res,
        403,
        "PRIVILEGE_ESCALATION",
        `Không thể gỡ vai trò '${req.role.code}' vì bạn không có quyền: ${missing.join(", ")}.`,
      );
    const hasRole = req.target.roles.some(
      (r) => String(r._id || r) === String(req.role._id),
    );
    if (hasRole && req.role.code === "super-admin") {
      if (await isLastSuperAdmin(req.target))
        return fail(
          res,
          409,
          "LAST_SUPER_ADMIN",
          "Không thể gỡ vai trò super-admin của người cuối cùng còn giữ vai trò này.",
        );
    }
    await User.updateOne(
      { _id: req.target._id },
      { $pull: { roles: req.role._id } },
    );
    res.status(204).end();
  },
);

module.exports = router;
