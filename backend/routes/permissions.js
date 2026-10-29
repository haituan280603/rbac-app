const express = require("express");
const Permission = require("../models/Permission");
const { authenticate, requirePermission } = require("../middleware/auth");
const { fail, detail, permissionView } = require("../utils/http");

const router = express.Router();
router.use(authenticate);

// ============ P1: GET /permissions ============
router.get("/", requirePermission("permissions:read"), async (req, res) => {
  const { resource } = req.query;
  if (resource !== undefined && typeof resource !== "string")
    return fail(
      res,
      400,
      "INVALID_QUERY_PARAMETER",
      "Tham số truy vấn không hợp lệ.",
      [detail("resource", "INVALID_VALUE", "resource phải là chuỗi.")],
    );

  const filter = resource ? { resource } : {};
  const perms = await Permission.find(filter).sort({ resource: 1, code: 1 });
  res.json({
    data: perms.map(permissionView),
    meta: { totalItems: perms.length },
  });
});

module.exports = router;
