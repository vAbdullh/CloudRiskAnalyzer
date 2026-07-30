import { Router } from 'express';
import {
  getConnections,
  getConnectionById,
  createConnection,
  updateConnection,
  deleteConnection,
  getPublicInfo,
} from '../controllers/connection.controller.js';
import { authCheck } from '../middleware/auth.middleware.js';

const router = Router();

// Public endpoint (unprotected)
router.get('/public-info', getPublicInfo);

// Protected endpoints (apply authCheck middleware)
router.get('/', authCheck, getConnections);
router.get('/:id', authCheck, getConnectionById);
router.post('/', authCheck, createConnection);
router.put('/:id', authCheck, updateConnection);
router.delete('/:id', authCheck, deleteConnection);

export default router;
