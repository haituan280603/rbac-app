const express = require("express");
const Role = require("../models/Role");
const User = require("../models/User");
const Permission = require("../models/Permission");
const { authenticate, requirePermission } = require("../middleware/auth");
const { missingPermissions } = require("../utils/rbac");
const {
  fail,
  detail,
  notAllowedFields,
  isObjectId,
  parsePaging,
  parseSort,
  escapeRegex,
  pageMeta,
  roleView,
} = require("../utils/http");

const router = express.Router();
router.use(authenticate);

// Số người dùng (chưa bị xóa) đang mang vai trò
const countUsers = (roleId) =>
  User.countDocuments({ roles: roleId, status: { $ne: "deleted" } });

// Kiểm tra mảng mã quyền: đúng kiểu và tồn tại trong danh mục
async function checkPermissionList(perms) {
  if (!Array.isArray(perms) || !perms.every((p) => typeof p === "string"))
    return {
      status: 400,
      code: "VALIDATION_ERROR",
      details: [
        detail(
          "permissions",
          "INVALID_TYPE",
          "permissions phải là mảng mã quyền.",
        ),
      ],
    };
  const known = new Set(
    (await Permission.find({ code: { $in: perms } })).map((p) => p.code),
  );
  const unknown = perms.filter((p) => !known.has(p));
  if (unknown.length)
    return {
      status: 400,
      code: "PERMISSION_NOT_FOUND",
      details: unknown.map((p) =>
        detail("permissions", "NOT_FOUND", `Quyền '${p}' không tồn tại.`),
      ),
    };
  return null;
}

async function loadRole(req, res, next) {
  const { roleId } = req.params;
  const role = isObjectId(roleId) ? await Role.findById(roleId) : null;
  if (!role) return fail(res, 404, "ROLE_NOT_FOUND", "Không tìm thấy vai trò.");
  req.target = role;
  next();
}

// ============ R1: GET /roles ============
router.get("/", requirePermission("roles:read"), async (req, res) => {
  const q = req.query;
  const details = [];
  const { page, limit } = parsePaging(q, details);
  const sort = parseSort(
    q.sort || "name",
    ["name", "code", "createdAt"],
    details,
  );
  if (details.length)
    return fail(
      res,
      400,
      "INVALID_QUERY_PARAMETER",
      "Tham số truy vấn không hợp lệ.",
      details,
    );

  const filter = {};
  if (q.q) {
    const re = { $regex: escapeRegex(String(q.q).trim()), $options: "i" };
    filter.$or = [{ name: re }, { code: re }];
  }

  const [items, totalItems] = await Promise.all([
    Role.find(filter)
      .sort({ ...sort, _id: 1 })
      .skip((page - 1) * limit)
      .limit(limit),
    Role.countDocuments(filter),
  ]);
  const counts = await Promise.all(items.map((r) => countUsers(r._id)));
  res.json({
    data: items.map((r, i) => roleView(r, counts[i])),
    meta: pageMeta(page, limit, totalItems),
  });
});

// ============ R2: POST /roles ============
router.post("/", requirePermission("roles:create"), async (req, res) => {
  const body = req.body || {};
  const details = notAllowedFields(body, [
    "code",
    "name",
    "description",
    "permissions",
  ]);
  if (!body.code) details.push(detail("code", "REQUIRED", "Thiếu mã vai trò."));
  else if (!/^[a-z][a-z0-9-]{2,49}$/.test(body.code))
    details.push(
      detail(
        "code",
        "INVALID_VALUE",
        "Mã vai trò: chữ thường, số, gạch nối; 3-50 ký tự; bắt đầu bằng chữ.",
      ),
    );
  if (!body.name)
    details.push(detail("name", "REQUIRED", "Thiếu tên vai trò."));
  else if (String(body.name).trim().length < 2)
    details.push(
      detail("name", "INVALID_VALUE", "Tên vai trò phải có ít nhất 2 ký tự."),
    );
  if (details.length)
    return fail(
      res,
      400,
      "VALIDATION_ERROR",
      "Dữ liệu đầu vào không hợp lệ.",
      details,
    );

  const perms = [...new Set(body.permissions || [])];
  const permError = await checkPermissionList(perms);
  if (permError)
    return fail(
      res,
      permError.status,
      permError.code,
      "Dữ liệu quyền không hợp lệ.",
      permError.details,
    );

  const missing = missingPermissions(perms, req.permissions);
  if (missing.length)
    return fail(
      res,
      403,
      "PRIVILEGE_ESCALATION",
      `Không thể cấp quyền bạn không có: ${missing.join(", ")}.`,
    );

  if (await Role.exists({ code: body.code }))
    return fail(res, 409, "ROLE_CODE_EXISTS", "Mã vai trò đã tồn tại.");

  const role = await Role.create({
    code: body.code,
    name: body.name,
    description: body.description ?? null,
    permissions: perms,
  });
  res
    .status(201)
    .location(`${req.baseUrl}/${role._id}`)
    .json(roleView(role, 0));
});

// ============ R3: GET /roles/:roleId ============
router.get(
  "/:roleId",
  requirePermission("roles:read"),
  loadRole,
  async (req, res) => {
    const count = await countUsers(req.target._id);
    res.json(roleView(req.target, count));
  },
);

// ============ R4: PATCH /roles/:roleId ============
router.patch(
  "/:roleId",
  requirePermission("roles:update"),
  loadRole,
  async (req, res) => {
    const body = req.body || {};
    const details = notAllowedFields(body, ["name", "description"]);
    if ("name" in body && String(body.name || "").trim().length < 2)
      details.push(
        detail("name", "INVALID_VALUE", "Tên vai trò phải có ít nhất 2 ký tự."),
      );
    if (details.length)
      return fail(
        res,
        400,
        "VALIDATION_ERROR",
        "Dữ liệu đầu vào không hợp lệ.",
        details,
      );

    if ("name" in body) req.target.name = String(body.name).trim();
    if ("description" in body) req.target.description = body.description;
    await req.target.save();
    const count = await countUsers(req.target._id);
    res.json(roleView(req.target, count));
  },
);

// ============ R5: DELETE /roles/:roleId ============
router.delete(
  "/:roleId",
  requirePermission("roles:delete"),
  loadRole,
  async (req, res) => {
    if (req.target.isSystem)
      return fail(
        res,
        409,
        "SYSTEM_ROLE_PROTECTED",
        "Không thể xóa vai trò hệ thống.",
      );
    const count = await countUsers(req.target._id);
    if (count > 0)
      return fail(
        res,
        409,
        "ROLE_IN_USE",
        "Vai trò đang được gán cho người dùng, không thể xóa.",
      );
    await Role.deleteOne({ _id: req.target._id });
    res.status(204).end();
  },
);

// ============ RP1: GET /roles/:roleId/permissions ============
router.get(
  "/:roleId/permissions",
  requirePermission("roles:read"),
  loadRole,
  async (req, res) => {
    const perms = await Permission.find({
      code: { $in: req.target.permissions },
    }).sort({ resource: 1, code: 1 });
    res.json({
      data: perms.map((p) => ({
        code: p.code,
        resource: p.resource,
        action: p.action,
        description: p.description,
      })),
      meta: { totalItems: perms.length },
    });
  },
);

// ============ RP2: PUT /roles/:roleId/permissions ============
router.put(
  "/:roleId/permissions",
  requirePermission("roles:update"),
  loadRole,
  async (req, res) => {
    if (req.target.isSystem)
      return fail(
        res,
        409,
        "SYSTEM_ROLE_PROTECTED",
        "Không thể thay đổi bộ quyền của vai trò hệ thống.",
      );

    const body = req.body || {};
    const perms = [...new Set(body.permissions || [])];
    const permError = await checkPermissionList(perms);
    if (permError)
      return fail(
        res,
        permError.status,
        permError.code,
        "Dữ liệu quyền không hợp lệ.",
        permError.details,
      );

    // Chống leo thang trên PHẦN THAY ĐỔI: quyền thêm vào và quyền bị bớt đi
    const before = new Set(req.target.permissions);
    const after = new Set(perms);
    const added = perms.filter((p) => !before.has(p));
    const removed = [...before].filter((p) => !after.has(p));
    const changed = [...added, ...removed];
    const missing = missingPermissions(changed, req.permissions);
    if (missing.length)
      return fail(
        res,
        403,
        "PRIVILEGE_ESCALATION",
        `Không thể thay đổi các quyền bạn không có: ${missing.join(", ")}.`,
      );

    req.target.permissions = perms;
    await req.target.save();
    const count = await countUsers(req.target._id);
    res.json(roleView(req.target, count));
  },
);

module.exports = router;
