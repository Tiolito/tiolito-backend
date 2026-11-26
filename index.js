// 1. Cargar dotenv obligatoriamente en la línea 1
require('dotenv').config();

// 2. Luego los demás imports
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const app = express();
const http = require('http');
const { Server } = require('socket.io');

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

io.on('connection', (socket) => {
  console.log('Cliente/Comercio conectado vía Socket:', socket.id);

  socket.on('join_merchant_room', (merchantId) => {
    socket.join(`merchant_${merchantId}`);
    console.log(`Comercio unido a la sala: merchant_${merchantId}`);
  });

  // 👈 NUEVO: Unir al cliente a su propia sala
  socket.on('join_client_room', (clientId) => {
    socket.join(`client_${clientId}`);
    console.log(`Cliente unido a la sala: client_${clientId}`);
  });

  // 👉 NUEVO: Unir al agente a su propia sala
  socket.on('join_agent_room', (agentId) => {
    if (!agentId) return;
    socket.join(`agent_${agentId}`);
    console.log(`Agente unido a la sala: agent_${agentId}`);
  });

  socket.on('join_admin_room', () => {
  socket.join('admin_room');
  console.log('Admin unido a la sala: admin_room');
});

  socket.on('disconnect', () => {
    console.log('Socket desconectado:', socket.id);
  });
});
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_jwt';
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Forzar hora de Guatemala en todas las conexiones de PostgreSQL
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'America/Guatemala';");
});

// Ruta raíz de bienvenida
app.get('/', (req, res) => {
  res.json({
    app: "Tiolito API",
    estado: "¡Servidor funcionando al 100%!",
    conexion: "Conectado a Supabase exitosamente"
  });
});

// Ruta para probar la base de datos desde el navegador
app.get('/api/test-db', async (req, res) => {
  try {
    const resultado = await pool.query('SELECT NOW()');
    res.json({
      exito: true,
      mensaje: "¡Consulta a Supabase exitosa!",
      tiempo_servidor_db: resultado.rows[0].now
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      exito: false,
      error: "Error al consultar la base de datos",
      detalles: error.message
    });
  }
});

// Probar conexión al iniciar
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error al conectar a la base de datos:', err.stack);
  }
  console.log('¡Conexión exitosa a PostgreSQL! 🗄️');
  release();
});

// ==========================================
// MIDDLEWARE: Verificar Token JWT
// ==========================================
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader) {
        return res.status(401).json({ success: false, error: "Acceso denegado. Token no proporcionado." });
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: "Token malformado." });
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, error: "Token inválido o expirado." });
        }
        
        try {
            // 🛡️ Comprobamos que este token sea la única sesión activa en la base de datos
            const userResult = await pool.query(
                'SELECT active_token FROM users WHERE id = $1',
                [decoded.id]
            );

            if (userResult.rows.length === 0) {
                return res.status(401).json({ success: false, error: "Usuario no encontrado." });
            }

            const dbToken = userResult.rows[0].active_token;

            // ⚠️ Si el token actual no coincide con el de la base de datos, rechazamos la petición
            if (!dbToken || dbToken !== token) {
                return res.status(401).json({ 
                    success: false, 
                    error: "SESSION_EXPIRED_OTHER_DEVICE",
                    message: "Tu sesión se cerró porque la cuenta se abrió en otro dispositivo." 
                });
            }

            req.user = decoded;
            next();

        } catch (dbError) {
            console.error("ERROR AL VERIFICAR SESIÓN ACTIVA:", dbError);
            return res.status(500).json({ success: false, error: "Error interno del servidor." });
        }
    });
};

// ==========================================
// MIDDLEWARE: Validar Rol Autorizado
// ==========================================
const requireRole = (...allowedRoles) => {
    const normalizedAllowed = allowedRoles.map(r => String(r).toUpperCase());

    return (req, res, next) => {
        const userRole = String(req.user?.role || '').toUpperCase();
        if (!userRole || !normalizedAllowed.includes(userRole)) {
            return res.status(403).json({
                success: false,
                error: 'Acceso denegado. No tienes permisos para realizar esta operación.'
            });
        }
        next();
    };
};

const round2 = (val) => Math.round((Number(val) + Number.EPSILON) * 100) / 100;

// ==========================================
// 3. ENDPOINT: GET /api/wallets/:user_id
// ==========================================
app.get('/api/wallets/:user_id', verifyToken, async (req, res) => {
    const { user_id } = req.params;
    const requesterId = String(req.user?.id || '');
    const requesterRole = String(req.user?.role || '').toUpperCase();

    if (requesterRole !== 'ADMIN' && String(user_id) !== requesterId) {
        return res.status(403).json({ success: false, error: 'Acceso denegado.' });
    }

    try {
        const result = await pool.query(
            'SELECT w.id, w.user_id, w.balance, w.currency, w.updated_at, u.full_name, u.role FROM wallets w JOIN users u ON w.user_id = u.id WHERE w.user_id::text = $1::text',
            [String(user_id)]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Billetera no encontrada para este usuario" });
        }

        res.status(200).json({
            success: true,
            wallet: result.rows[0]
        });

    } catch (error) {
        console.error("Error en GET /api/wallets:", error);
        res.status(500).json({ success: false, error: "Error interno al consultar la billetera" });
    }
});

// ==========================================
// ENDPOINT: POST /api/login (Autenticación JWT)
// ==========================================
app.post('/api/login', async (req, res) => {
  const phone_number = req.body.phone_number || req.body.email;
  const inputPassword = req.body.pin || req.body.password;

  try {
    const userResult = await pool.query(
      'SELECT id, full_name, role, tier, pin_hash FROM users WHERE phone_number = $1',
      [phone_number]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Usuario no encontrado" });
    }

    const user = userResult.rows[0];

    // Validación estricta únicamente mediante bcrypt
    const isValidPassword = await bcrypt.compare(inputPassword, user.pin_hash);

    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.full_name },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    // Guardar este nuevo token como la única sesión activa del usuario
    await pool.query(
      'UPDATE users SET active_token = $1 WHERE id = $2',
      [token, user.id]
    );

    return res.json({ success: true, token, role: user.role, user_id: user.id, name: user.full_name, tier: user.tier });

  } catch (error) {
    console.error("ERROR EN EL LOGIN:", error);
    return res.status(500).json({ success: false, error: "Error interno al iniciar sesión" });
  }
});

// ==========================================
// 4. ENDPOINT: GET /api/transactions/:user_id
// ==========================================
app.get('/api/transactions/:user_id', verifyToken, async (req, res) => {
    const { user_id } = req.params;
    const requesterId = String(req.user?.id || '');
    const requesterRole = String(req.user?.role || '').toUpperCase();

    if (requesterRole !== 'ADMIN' && String(user_id) !== requesterId) {
        return res.status(403).json({ success: false, error: 'Acceso denegado.' });
    }

    try {
        const result = await pool.query(
            'SELECT * FROM transactions WHERE client_id::text = $1::text ORDER BY created_at DESC',
            [String(user_id)]
        );

        res.status(200).json({
            success: true,
            count: result.rows.length,
            transactions: result.rows
        });

    } catch (error) {
        console.error("Error en GET /api/transactions:", error);
        res.status(500).json({ success: false, error: "Error interno al consultar transacciones" });
    }
});

// Función auxiliar para estandarizar teléfonos (solo dígitos)
const normalizePhone = (phone) => String(phone || '').replace(/\D/g, '').trim();

// ==========================================
// 5. ENDPOINT: POST /api/transfer (Transferencia P2P por Teléfono)
// ==========================================
app.post('/api/transfer', verifyToken, validarLimitesAML, async (req, res) => {
    const sender_id = req.user.id; // Obtenemos el ID del emisor desde el Token JWT
    const { receiver_phone, amount } = req.body;

    const cleanReceiverPhone = normalizePhone(receiver_phone);
    const rawAmount = parseFloat(amount);
    const transferAmount = Number.isFinite(rawAmount) ? Math.round(rawAmount * 100) / 100 : NaN;

    if (!cleanReceiverPhone || cleanReceiverPhone.length < 8 || Number.isNaN(transferAmount) || transferAmount <= 0) {
        return res.status(400).json({ success: false, error: "Ingresa un número de teléfono y un monto válido." });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Obtener datos del emisor
        const senderResult = await client.query('SELECT id, phone_number, balance FROM users WHERE id = $1 FOR UPDATE', [sender_id]);
        if (senderResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Usuario emisor no encontrado" });
        }

        const sender = senderResult.rows[0];
        const cleanSenderPhone = normalizePhone(sender.phone_number);

        // 2. Validar si intenta transferirse a su propio número (normalizado)
        if (cleanSenderPhone && cleanSenderPhone === cleanReceiverPhone) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "No puedes transferir fondos a la misma billetera" });
        }

        // 3. Buscar al receptor por su número de teléfono normalizado (incluyendo 'role')
        const receiverResult = await client.query(
            `SELECT id, phone_number, balance, role
             FROM users
             WHERE REGEXP_REPLACE(COALESCE(phone_number, ''), '\\D', '', 'g') = $1
             FOR UPDATE`,
            [cleanReceiverPhone]
        );
        if (receiverResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "El número de destino no está registrado en el sistema" });
        }

        const receiver = receiverResult.rows[0];

        // Doble validación por si los IDs coinciden
        if (sender.id === receiver.id) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "No puedes transferir fondos a la misma billetera" });
        }

        // 🛡️ CONTROL ANTI-COMERCIO EN CUENTAS CLIENTE:
        // Alerta en 10 remitentes únicos al mes | Bloqueo a partir de 15 remitentes únicos al mes
        if (String(receiver.role || '').toUpperCase() === 'CLIENT') {
            const remitentesMesRes = await client.query(
                `SELECT COUNT(DISTINCT agent_id) AS remitentes_unicos
                 FROM transactions
                 WHERE client_id::text = $1::text
                   AND UPPER(type) = 'TRANSFER-OUT'
                   AND EXTRACT(MONTH FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(MONTH FROM (NOW() AT TIME ZONE 'America/Guatemala'))
                   AND EXTRACT(YEAR FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(YEAR FROM (NOW() AT TIME ZONE 'America/Guatemala'))`,
                [String(receiver.id)]
            );

            const totalRemitentes = parseInt(remitentesMesRes.rows[0].remitentes_unicos || 0, 10);

            if (totalRemitentes >= 10 && totalRemitentes < 15) {
                console.warn(
                    `⚠️ ALERTA PATRÓN DE COBRO (CLIENT): user_id=${receiver.id}, phone=${receiver.phone_number}, remitentes_unicos_mes=${totalRemitentes}`
                );
            }

            if (totalRemitentes >= 15) {
                await client.query('ROLLBACK');

                // Notificar a la cuenta receptora que ya alcanzó su límite mensual como CLIENT
                io.to(`client_${receiver.id}`).emit('merchant_upgrade_required', {
                    code: "MERCHANT_UPGRADE_REQUIRED",
                    message: "Tu cuenta personal alcanzó el límite mensual de 15 personas distintas recibiendo transferencias. Pásate a Cuenta de Comercio para seguir cobrando sin este tope."
                });

                return res.status(400).json({
                    success: false,
                    code: "RECEIVER_LIMIT_REACHED",
                    error: "La cuenta de destino alcanzó el límite mensual de transferencias recibidas de distintos usuarios (15) para cuentas personales."
                });
            }
        }

        // 4. Validar saldo suficiente (redondeado a 2 decimales para evitar errores de punto flotante)
        const senderBalance = Math.round(parseFloat(sender.balance || 0) * 100) / 100;
        if (senderBalance < transferAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Saldo insuficiente para realizar la transferencia" });
        }

        // 5. Descontar al emisor
        await client.query(
            'UPDATE users SET balance = ROUND((COALESCE(balance, 0) - $1)::numeric, 2) WHERE id = $2',
            [transferAmount, sender_id]
        );

        // 6. Acreditar al receptor
        await client.query(
            'UPDATE users SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2) WHERE id = $2',
            [transferAmount, receiver.id]
        );

        // 7. Registrar la transacción
        const transactionResult = await client.query(
            `INSERT INTO transactions (agent_id, client_id, amount, type, created_at)
             VALUES ($1, $2, $3, 'TRANSFER-OUT', NOW()) RETURNING *;`,
            [sender_id, receiver.id, transferAmount]
        );

        await client.query('COMMIT');

        io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

        // Consultar nombres de emisor y receptor para el comprobante
        const userNamesRes = await client.query(
            'SELECT id, full_name, phone_number FROM users WHERE id = $1 OR id = $2',
            [sender_id, receiver.id]
        );

        const senderInfo = userNamesRes.rows.find(u => u.id === sender_id) || { full_name: req.user.name || 'Emisor', phone_number: sender.phone_number };
        const receiverInfo = userNamesRes.rows.find(u => u.id === receiver.id) || { full_name: 'Destinatario', phone_number: cleanReceiverPhone };

        // 👈 Usamos directamente el ID de la base de datos para mantener el formato corto TRX-ID
        const shortFolio = `TRX-${transactionResult.rows[0].id}`;

        // 🚀 Preparamos el paquete de datos para el socket en tiempo real
        const transferPayload = {
            folio: shortFolio,
            id: transactionResult.rows[0].id,
            type: "Transferencia P2P",
            sender_name: senderInfo.full_name,
            sender_phone: senderInfo.phone_number,
            receiver_name: receiverInfo.full_name,
            receiver_phone: cleanReceiverPhone,
            amount: transferAmount,
            created_at: new Date()
        };

        // 🚀 Notificar instantáneamente al receptor en su propia sala
        io.to(`client_${receiver.id}`).emit('transfer_received', transferPayload);

        res.status(200).json({
            success: true,
            transaction: transferPayload
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error en /api/transfer:", error);
        res.status(500).json({ success: false, error: "Ocurrió un error al procesar la transferencia. Intenta de nuevo." });
    } finally {
        client.release();
    }
});

// ==========================================
// ESTADO DE LÍMITE COMERCIAL PARA CUENTAS CLIENTE
// ==========================================
app.get('/api/account/merchant-status', verifyToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const userRes = await pool.query(
            'SELECT id, role FROM users WHERE id = $1',
            [userId]
        );

        if (userRes.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
        }

        const role = String(userRes.rows[0].role || '').toUpperCase();

        if (role !== 'CLIENT') {
            return res.status(200).json({
                success: true,
                upgradeRequired: false,
                uniqueSenders: 0,
                limit: 15
            });
        }

        const countRes = await pool.query(
            `SELECT COUNT(DISTINCT agent_id) AS remitentes_unicos
             FROM transactions
             WHERE client_id::text = $1::text
               AND UPPER(type) = 'TRANSFER-OUT'
               AND EXTRACT(MONTH FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(MONTH FROM (NOW() AT TIME ZONE 'America/Guatemala'))
               AND EXTRACT(YEAR FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(YEAR FROM (NOW() AT TIME ZONE 'America/Guatemala'))`,
            [String(userId)]
        );

        const uniqueSenders = parseInt(countRes.rows[0]?.remitentes_unicos || 0, 10);
        const upgradeRequired = uniqueSenders >= 15;

        return res.status(200).json({
            success: true,
            upgradeRequired,
            uniqueSenders,
            limit: 15,
            message: upgradeRequired
                ? 'Tu cuenta personal alcanzó el límite mensual de 15 personas distintas recibiendo transferencias. Pásate a Cuenta de Comercio para seguir cobrando sin este tope.'
                : null
        });
    } catch (error) {
        console.error('Error en /api/account/merchant-status:', error);
        return res.status(500).json({ success: false, error: 'No se pudo verificar el estado de la cuenta' });
    }
});

// ==========================================
// 8. ENDPOINT: POST /api/merchant/refund (Devolución asumida por el comercio)
// ==========================================
app.post('/api/merchant/refund', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    const { transaction_id } = req.body;
    const merchantId = String(req.user.id);

    if (!transaction_id) {
        return res.status(400).json({ success: false, error: "ID de transacción no proporcionado" });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const cleanId = String(transaction_id).replace('TRX-', '').trim();

        // 1. Buscar y bloquear la transacción original
        const txResult = await client.query(
            `SELECT * FROM transactions 
             WHERE id::text = $1 
               AND (agent_id::text = $2::text OR merchant_id::text = $2::text)
             FOR UPDATE`,
            [cleanId, merchantId]
        );

        if (txResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Transacción no encontrada o no autorizada" });
        }

        const transaction = txResult.rows[0];
        const refundAmount = round2(parseFloat(transaction.amount));
        if (isNaN(refundAmount) || refundAmount <= 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Monto de transacción inválido para reembolso" });
        }

        const clientId = transaction.client_id ? String(transaction.client_id) : null;

        // Bloquear cuentas involucradas en orden determinista para evitar deadlocks
        const accountIds = clientId
            ? [merchantId, clientId].sort((a, b) => a.localeCompare(b))
            : [merchantId];

        const lockedUsers = new Map();
        for (const accId of accountIds) {
            const uRes = await client.query(
                'SELECT id, balance FROM users WHERE id::text = $1::text FOR UPDATE',
                [accId]
            );
            if (uRes.rows.length > 0) {
                lockedUsers.set(accId, uRes.rows[0]);
            }
        }

        const merchantRow = lockedUsers.get(merchantId);
        if (!merchantRow) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Comercio no encontrado" });
        }

        const merchantBalance = round2(parseFloat(merchantRow.balance || 0));
        if (merchantBalance < refundAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente en comercio para cubrir la devolución de Q${refundAmount.toFixed(2)} (disponible: Q${merchantBalance.toFixed(2)}).`
            });
        }

        // 2. Devolver el monto íntegro al cliente (si existe)
        if (clientId && lockedUsers.has(clientId)) {
            await client.query(
                'UPDATE users SET balance = ROUND((balance + $1)::numeric, 2) WHERE id::text = $2::text',
                [refundAmount, clientId]
            );
        }

        // 3. El comercio asume el monto íntegro de la devolución (la comisión ya cobrada no se toca)
        await client.query(
            'UPDATE users SET balance = ROUND((balance - $1)::numeric, 2) WHERE id::text = $2::text',
            [refundAmount, merchantId]
        );
        await client.query(
            'UPDATE wallets SET balance = ROUND((balance - $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
            [refundAmount, merchantId]
        );

        // 4. Eliminar el registro original de la venta (o conservar si prefieres historial completo)
        await client.query('DELETE FROM transactions WHERE id::text = $1::text', [cleanId]);

        // 5. Registrar la transacción de reembolso
        const refundTx = await client.query(
            `INSERT INTO transactions (agent_id, client_id, merchant_id, amount, type, created_at)
             VALUES ($1, $2, $3, $4, 'REFUND', NOW()) RETURNING id, created_at`,
            [transaction.agent_id, clientId, transaction.merchant_id, refundAmount]
        );

        await client.query('COMMIT');

        io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

        if (clientId) {
            io.to(`client_${clientId}`).emit('transaction_update', {
                type: 'REFUND',
                message: `Has recibido una devolución de Q${refundAmount.toFixed(2)}`,
                amount: refundAmount
            });
        }

        return res.json({
            success: true,
            message: `Reembolso de Q${refundAmount.toFixed(2)} procesado con éxito (asumido por el comercio)`,
            refund_transaction_id: refundTx.rows[0].id
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (refund):', rollbackErr);
        }
        console.error("Error al procesar la devolución:", error);
        return res.status(500).json({ success: false, error: "Error interno al procesar el reembolso." });
    } finally {
        client.release();
    }
});

// ==========================================
// 9. ENDPOINT: GET /api/client/balance (Consultar saldo)
// ==========================================
app.get('/api/client/balance', verifyToken, async (req, res) => {
    const userIdFromToken = req.user.id;

    try {
        const result = await pool.query(
            'SELECT id, full_name, balance FROM users WHERE id = $1',
            [userIdFromToken]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        res.json({ success: true, client: result.rows[0] });
    } catch (error) {
        console.error("Error al consultar saldo:", error);
        res.status(500).json({ success: false, error: "Error al obtener el saldo" });
    }
});

app.get('/api/client/transactions', verifyToken, async (req, res) => {
    const userIdFromToken = req.user.id;

    try {
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type AS original_type,
                t.bank_name,
                t.account_number,
                t.account_type,
                CASE 
                    WHEN UPPER(t.type) = 'MERCHANT-PAYMENT' THEN 'Pago a Comercio'
                    WHEN UPPER(t.type) IN ('CASH-IN', 'CASH_IN') THEN 'Depósito (Cash-In)'
                    WHEN UPPER(t.type) IN ('CASH-OUT', 'CASH_OUT') THEN 'Retiro (Cash-Out)'
                    WHEN UPPER(t.type) = 'REFUND' THEN 'Reembolso Recibido'
                    WHEN UPPER(t.type) LIKE 'BANK-WITHDRAWAL%' OR UPPER(t.type) LIKE '%ACH%' THEN
                        CASE
                            WHEN UPPER(t.type) LIKE '%PENDING%' OR UPPER(t.type) LIKE '%PENDIENTE%' THEN 'BANK-WITHDRAWAL-PENDING'
                            WHEN UPPER(t.type) LIKE '%PAID%' OR UPPER(t.type) LIKE '%COMPLETED%' OR UPPER(t.type) LIKE '%APPROVED%' THEN 'BANK-WITHDRAWAL-PAID'
                            ELSE 'BANK-WITHDRAWAL'
                        END
                    WHEN UPPER(t.type) LIKE '%TRANSFER%' AND t.client_id::text = $1::text THEN 'TRANSFER-IN'
                    WHEN UPPER(t.type) LIKE '%TRANSFER%' AND t.agent_id::text = $1::text THEN 'TRANSFER-OUT'
                    WHEN t.client_id::text = $1::text THEN 'TRANSFER-IN'
                    ELSE 'TRANSFER-OUT'
                END AS display_type,
                t.created_at, 
                COALESCE(merchant_user.full_name, agent_user.full_name, 'Comercio Local') AS merchant_name,
                COALESCE(agent_user.full_name, sender.full_name, 'Agente Autorizado') AS agent_name,
                COALESCE(client_user.full_name, receiver.full_name, 'Cliente') AS client_user_name,
                sender.full_name AS sender_name,
                sender.phone_number AS sender_phone,
                receiver.full_name AS receiver_name,
                receiver.phone_number AS receiver_phone,
                client_user.phone_number AS client_phone
            FROM transactions t
            LEFT JOIN users merchant_user ON t.merchant_id::text = merchant_user.id::text
            LEFT JOIN users agent_user ON t.agent_id::text = agent_user.id::text
            LEFT JOIN users sender ON t.agent_id::text = sender.id::text
            LEFT JOIN users receiver ON t.client_id::text = receiver.id::text
            LEFT JOIN users client_user ON t.client_id::text = client_user.id::text
            WHERE t.client_id::text = $1::text OR t.agent_id::text = $1::text
            ORDER BY t.created_at DESC
            LIMIT 50
        `;
        const result = await pool.query(query, [userIdFromToken]);

        res.json({ success: true, transactions: result.rows });
    } catch (error) {
        console.error("Error al obtener historial del cliente:", error);
        res.status(500).json({ success: false, error: "Error al obtener el historial de transacciones" });
    }
});

// ==========================================
// ENDPOINT: GET /api/agent/transactions (Historial de transacciones del agente)
// ==========================================
app.get('/api/agent/transactions', verifyToken, requireRole('AGENT'), async (req, res) => {
  const agent_id = req.user?.id || req.user?.userId;
  
  if (!agent_id) {
    return res.status(403).json({ success: false, message: 'Token sin ID válido' });
  }

  const { search, type } = req.query;

  try {
    let query = `
      SELECT 
        t.id,
        t.type,
        t.amount,
        t.created_at,
        COALESCE(u.full_name, 'Cliente Genérico') AS client_name,
        COALESCE(u.phone_number, '') AS client_phone,
        COALESCE(agent_user.full_name, $2, 'Agente Autorizado') AS agent_name
      FROM transactions t 
      LEFT JOIN users u ON t.client_id::text = u.id::text 
      LEFT JOIN users agent_user ON t.agent_id::text = agent_user.id::text
      WHERE t.agent_id::text = $1::text
      -- 🌟 EXCLUIR LAS SOLICITUDES DE RETIRO ACH DEL HISTORIAL DE CAJA
      AND UPPER(t.type) NOT IN (
        'BANK-WITHDRAWAL-PENDING', 
        'AGENT-BANK-WITHDRAWAL-PENDING', 
        'BANK-WITHDRAWAL-COMPLETED'
      )
    `;
    
    const queryParams = [String(agent_id), req.user?.name || 'Agente Autorizado'];

    if (search && search.trim() !== '') {
      queryParams.push(`%${search.trim()}%`);
      query += ` AND (
        u.phone_number ILIKE $${queryParams.length} 
        OR u.full_name ILIKE $${queryParams.length}
      )`;
    }

    if (type && type !== 'ALL') {
      const normalizedType = type.toLowerCase().replace('_', '-');
      queryParams.push(normalizedType);
      query += ` AND (LOWER(t.type) = $${queryParams.length} OR LOWER(REPLACE(t.type, '_', '-')) = $${queryParams.length})`;
    }

    query += ` ORDER BY t.created_at DESC LIMIT 50`;

    const result = await pool.query(query, queryParams);
    res.json({ success: true, data: result.rows });

  } catch (error) {
    console.error('Error al obtener historial del agente:', error);
    res.status(500).json({ success: false, message: 'Error interno del servidor' });
  }
});

// ==========================================
// CASH-IN (Depósito en efectivo por Agente)
// ==========================================
app.post('/api/cash-in', verifyToken, requireRole('AGENT'), validarLimitesAML, async (req, res) => {
  const agent_id = req.user.id;
  const rawPhone = req.body.phone_number || req.body.client_phone || req.body.phone;
  const cleanPhone = normalizePhone(rawPhone);
  const rawAmount = parseFloat(req.body.amount ?? req.body.monto);
  const depositAmount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;

  if (!cleanPhone || cleanPhone.length < 8 || Number.isNaN(depositAmount) || depositAmount <= 0) {
    return res.status(400).json({ success: false, error: "Falta un teléfono válido o un monto mayor a cero" });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Bloquear agente primero para evitar carreras en su caja/saldo
    const agentRes = await client.query(
      'SELECT id, balance, full_name FROM users WHERE id::text = $1::text FOR UPDATE',
      [String(agent_id)]
    );

    if (agentRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: "Agente no encontrado" });
    }

    const agentData = agentRes.rows[0];
    const agentBalance = round2(parseFloat(agentData.balance || 0));

    if (agentBalance < depositAmount) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        error: `Saldo de agente insuficiente. Tu saldo disponible es de Q${agentBalance.toFixed(2)} y necesitas Q${depositAmount.toFixed(2)}.`
      });
    }

    // Buscar y bloquear al cliente por teléfono normalizado
    const clientLookup = await client.query(
      `SELECT id, full_name, phone_number, balance
       FROM users
       WHERE REGEXP_REPLACE(COALESCE(phone_number, ''), '\\D', '', 'g') = $1
       FOR UPDATE`,
      [cleanPhone]
    );

    let client_id;
    let newBalance;
    let clientName = 'Cliente Validado';

    if (clientLookup.rows.length === 0) {
      const tempPinHash = await bcrypt.hash(Math.floor(100000 + Math.random() * 900000).toString(), 10);
      const newUser = await client.query(
        `INSERT INTO users (phone_number, pin_hash, balance, full_name, role, is_verified)
         VALUES ($1, $2, $3, $4, 'CLIENT', TRUE)
         RETURNING id, balance, full_name`,
        [cleanPhone, tempPinHash, depositAmount, 'Cliente Nuevo']
      );
      client_id = newUser.rows[0].id;
      newBalance = depositAmount;
      clientName = newUser.rows[0].full_name;
    } else {
      const targetClient = clientLookup.rows[0];
      client_id = targetClient.id;
      clientName = targetClient.full_name || 'Cliente';
      const currentClientBalance = round2(parseFloat(targetClient.balance || 0));
      newBalance = round2(currentClientBalance + depositAmount);

      await client.query(
        'UPDATE users SET balance = $1 WHERE id::text = $2::text',
        [newBalance, String(client_id)]
      );
    }

    // Descontar del agente en users y wallets si existe registro
    const newAgentBalance = round2(agentBalance - depositAmount);
    await client.query(
      'UPDATE users SET balance = $1 WHERE id::text = $2::text',
      [newAgentBalance, String(agent_id)]
    );
    await client.query(
      'UPDATE wallets SET balance = ROUND((balance - $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
      [depositAmount, String(agent_id)]
    );

    const realAgentName = agentData.full_name || 'Punto Agente Tiolito';
    const folioUnico = `TRX-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

    const txResult = await client.query(
      `INSERT INTO transactions (agent_id, client_id, amount, type, created_at)
       VALUES ($1, $2, $3, 'CASH-IN', NOW())
       RETURNING id, created_at`,
      [agent_id, client_id, depositAmount]
    );
    const transactionIdShort = txResult.rows[0].id;

    await client.query('COMMIT');

    io.to(`client_${client_id}`).emit('balance_updated', {
      type: "Depósito (Cash-In)",
      amount: depositAmount,
      created_at: new Date()
    });

    io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

    return res.json({
      success: true,
      new_balance: newBalance,
      transaction: {
        id: transactionIdShort,
        folio: folioUnico,
        type: "Depósito (Cash-In)",
        agent_name: realAgentName,
        client_name: clientName,
        client_phone: cleanPhone,
        amount: depositAmount,
        created_at: new Date()
      }
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Error en ROLLBACK (cash-in):', rollbackErr);
    }
    console.error("ERROR EN CASH-IN:", error);
    return res.status(500).json({ success: false, error: "Error interno al procesar el depósito." });
  } finally {
    client.release();
  }
});

// ==========================================
// CÁLCULO DE COMISIONES Y REPARTO (CASH-OUT)
// ==========================================
function calcularYDividirComision(montoRetiro) {
    let comisionTotal = 0;

    // Rangos definidos para retiros (hasta Q2,000.00 máx)
    if (montoRetiro <= 200.00) {
        comisionTotal = 2.00;
    } else if (montoRetiro <= 500.00) {
        comisionTotal = 4.00;
    } else if (montoRetiro <= 1000.00) {
        comisionTotal = 8.00;
    } else if (montoRetiro <= 2000.00) {
        comisionTotal = 16.00;
    } else {
        throw new Error("El monto excede el límite máximo permitido por transacción (Q2,000.00).");
    }

    // Distribución exacta del porcentaje
    const comisionAgente = Number((comisionTotal * 0.70).toFixed(2));  // 70% para el agente
    const comisionTiolito = Number((comisionTotal * 0.30).toFixed(2)); // 30% para administración

    return {
        montoRetiro,
        comisionTotal,
        comisionAgente,
        comisionTiolito
    };
}

// ==========================================
// CASH-OUT (Retiro en efectivo por Agente)
// ==========================================
app.post('/api/cash-out', verifyToken, requireRole('AGENT'), validarLimitesAML, async (req, res) => {
  const agent_id = req.user.id;
  const agentNameFromToken = req.user.name || 'Punto Agente Tiolito';
  const rawPhone = req.body.client_phone || req.body.phone || req.body.phoneNumber || req.body.phone_number;
  const cleanPhone = normalizePhone(rawPhone);
  const rawAmount = parseFloat(req.body.amount ?? req.body.monto);
  const withdrawAmount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;
  const code = req.body.code ? String(req.body.code).trim() : null;

  if (!cleanPhone || cleanPhone.length < 8 || Number.isNaN(withdrawAmount) || withdrawAmount <= 0) {
    return res.status(400).json({ success: false, error: "Falta un teléfono válido o un monto mayor a cero" });
  }

  let comisionesBase;
  try {
    comisionesBase = calcularYDividirComision(withdrawAmount);
  } catch (limitErr) {
    return res.status(400).json({ success: false, error: limitErr.message });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Buscar cliente/comercio por teléfono normalizado
    const clientLookup = await client.query(
      `SELECT id, balance, role, tier, full_name, phone_number
       FROM users
       WHERE REGEXP_REPLACE(COALESCE(phone_number, ''), '\\D', '', 'g') = $1`,
      [cleanPhone]
    );

    if (clientLookup.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: "Cliente o Comercio no encontrado" });
    }

    const targetId = String(clientLookup.rows[0].id);
    const agentStrId = String(agent_id);

    // Bloquear en orden determinista para prevenir deadlocks
    const idsToLock = Array.from(new Set([targetId, agentStrId])).sort((a, b) => a.localeCompare(b));
    const lockedMap = new Map();

    for (const idItem of idsToLock) {
      const uRes = await client.query(
        'SELECT id, balance, role, tier, full_name, phone_number FROM users WHERE id::text = $1::text FOR UPDATE',
        [idItem]
      );
      if (uRes.rows.length > 0) {
        lockedMap.set(idItem, uRes.rows[0]);
      }
    }

    const targetUser = lockedMap.get(targetId);
    const agentUser = lockedMap.get(agentStrId);

    if (!targetUser || !agentUser) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: "Usuario o agente no encontrado" });
    }

    const userRole = String(targetUser.role || '').toUpperCase();
    const currentBalance = round2(parseFloat(targetUser.balance || 0));

    let comisiones;
    let totalDescuentoCliente;

    if (userRole === 'MERCHANT' || userRole === 'COMERCIO') {
      comisiones = {
        montoRetiro: withdrawAmount,
        comisionTotal: 0.00,
        comisionAgente: 0.00,
        comisionTiolito: 0.00
      };
      totalDescuentoCliente = withdrawAmount;
    } else {
      comisiones = {
        montoRetiro: withdrawAmount,
        comisionTotal: round2(comisionesBase.comisionTotal),
        comisionAgente: round2(comisionesBase.comisionAgente),
        comisionTiolito: round2(comisionesBase.comisionTiolito)
      };
      totalDescuentoCliente = round2(withdrawAmount + comisiones.comisionTotal);
    }

    if (currentBalance < totalDescuentoCliente) {
      await client.query('ROLLBACK');
      const errorMsg = (userRole === 'MERCHANT' || userRole === 'COMERCIO')
        ? `Saldo insuficiente. Tu saldo disponible es de Q${currentBalance.toFixed(2)}.`
        : `Saldo insuficiente. Necesitas Q${totalDescuentoCliente.toFixed(2)} (incluye Q${comisiones.comisionTotal.toFixed(2)} de comisión)`;

      return res.status(400).json({ success: false, error: errorMsg });
    }

    // Si viene código de retiro, validar y bloquear dentro de la transacción
    if (code) {
      const codeCheck = await client.query(
        `SELECT id, client_id, amount, status, expires_at
         FROM withdrawal_codes
         WHERE code = $1
         FOR UPDATE`,
        [code]
      );

      if (codeCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: "Código de retiro inválido." });
      }

      const codeRow = codeCheck.rows[0];
      if (String(codeRow.status).toUpperCase() !== 'PENDING') {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: "El código de retiro ya fue utilizado." });
      }

      if (new Date(codeRow.expires_at) <= new Date()) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: "El código de retiro ha expirado." });
      }

      if (String(codeRow.client_id) !== targetId) {
        await client.query('ROLLBACK');
        return res.status(400).json({ success: false, error: "El código de retiro no corresponde a este usuario." });
      }
    }

    const newBalance = round2(currentBalance - totalDescuentoCliente);
    const totalAbonoAgente = round2(withdrawAmount + comisiones.comisionAgente);
    const newAgentBalance = round2(parseFloat(agentUser.balance || 0) + totalAbonoAgente);

    // 1. Actualizar saldo del cliente/comercio
    await client.query(
      'UPDATE users SET balance = $1 WHERE id::text = $2::text',
      [newBalance, targetId]
    );

    // 2. Actualizar saldo del agente
    await client.query(
      'UPDATE users SET balance = $1 WHERE id::text = $2::text',
      [newAgentBalance, agentStrId]
    );
    await client.query(
      'UPDATE wallets SET balance = ROUND((balance + $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
      [totalAbonoAgente, agentStrId]
    );

    // 3. Abonar comisión a administración si hubo comisión
    if (comisiones.comisionTiolito > 0) {
      const adminResult = await client.query(
        "SELECT id FROM users WHERE UPPER(role) = 'ADMIN' OR phone_number = '00000000' ORDER BY id ASC LIMIT 1 FOR UPDATE"
      );

      if (adminResult.rows.length > 0) {
        const admin_id = String(adminResult.rows[0].id);
        await client.query(
          'UPDATE users SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2) WHERE id::text = $2::text',
          [comisiones.comisionTiolito, admin_id]
        );
        await client.query(
          'UPDATE wallets SET balance = ROUND((balance + $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
          [comisiones.comisionTiolito, admin_id]
        );
      }
    }

    // 4. Registrar transacción CASH-OUT y marcar código como usado
    const folioUnico = `TRX-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;
    const txResult = await client.query(
      `INSERT INTO transactions (agent_id, client_id, amount, type, created_at)
       VALUES ($1, $2, $3, 'CASH-OUT', NOW())
       RETURNING id, created_at`,
      [agent_id, targetUser.id, withdrawAmount]
    );
    const transactionIdShort = txResult.rows[0].id;

    // 5. Registrar desglose de comisiones en platform_commissions
    if (comisiones.comisionTiolito > 0 || comisiones.comisionAgente > 0) {
      await client.query(
        `INSERT INTO platform_commissions
          (transaction_id, source_type, gross_amount, commission_total, agent_commission, admin_commission, created_at)
         VALUES ($1, 'CASH-OUT', $2, $3, $4, $5, NOW())`,
        [
          transactionIdShort,
          withdrawAmount,
          comisiones.comisionTotal,
          comisiones.comisionAgente,
          comisiones.comisionTiolito
        ]
      );
    }

    if (code) {
      await client.query(
        "UPDATE withdrawal_codes SET status = 'USED' WHERE code = $1",
        [code]
      );
    }

    await client.query('COMMIT');

    io.to(`client_${targetUser.id}`).emit('balance_updated', {
      type: "Retiro (Cash-Out)",
      amount: withdrawAmount,
      commission: comisiones.comisionTotal,
      created_at: new Date()
    });

    io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

    return res.json({
      success: true,
      new_balance: newBalance,
      detalles_comision: comisiones,
      transaction: {
        id: transactionIdShort,
        folio: folioUnico,
        type: "Retiro (Cash-Out)",
        agent_name: agentUser.full_name || agentNameFromToken,
        client_name: targetUser.full_name || 'Cliente',
        client_phone: targetUser.phone_number || cleanPhone,
        amount: withdrawAmount,
        commission: comisiones.comisionTotal,
        created_at: new Date()
      }
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Error en ROLLBACK (cash-out):', rollbackErr);
    }
    console.error("ERROR EN CASH-OUT:", error);
    return res.status(500).json({ success: false, error: "Error interno al procesar el retiro." });
  } finally {
    client.release();
  }
});

// Ruta para validar un código o QR de retiro
app.post('/api/cash-out/validate-code', verifyToken, requireRole('AGENT'), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ success: false, error: 'Ingresa un código o escanea un QR válido' });
    }

    // 1. Buscar el código en la base de datos
    const codeResult = await pool.query(
      `SELECT wc.*, u.phone_number, u.full_name
       FROM withdrawal_codes wc
       JOIN users u ON wc.client_id = u.id
       WHERE wc.code = $1 AND wc.status = 'PENDING' AND wc.expires_at > NOW()`,
      [code]
    );

    if (codeResult.rows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'El código es inválido, ya fue utilizado o ha expirado.' 
      });
    }

    const item = codeResult.rows[0];

    return res.json({
      success: true,
      data: {
        code: item.code,
        phone_number: item.phone_number,
        client_name: item.full_name,
        amount: item.amount
      }
    });

  } catch (error) {
    console.error('Error al validar código de retiro:', error);
    return res.status(500).json({ success: false, error: 'Error al procesar la validación' });
  }
}); 

// Endpoint para Historial Detallado de Transacciones
app.get('/api/transactions/history', verifyToken, requireRole('ADMIN', 'AGENT'), async (req, res) => {
  try {
    const { agent_id, search, type, date } = req.query;

    let query = `
      SELECT 
        t.id,
        t.type,
        t.amount,
        t.status,
        t.created_at,
        u.full_name AS client_name,
        u.phone_number AS client_phone,
        a.full_name AS agent_name
      FROM transactions t
      LEFT JOIN users u ON t.client_id = u.id
      LEFT JOIN users a ON t.agent_id = a.id
      WHERE 1=1
    `;

    const queryParams = [];

    // Filtro por agente (opcional según la necesidad)
    if (agent_id) {
      queryParams.push(agent_id);
      query += ` AND t.agent_id = $${queryParams.length}`;
    }

    // Filtro por búsqueda (teléfono o nombre)
    if (search) {
      queryParams.push(`%${search.trim()}%`);
      query += ` AND (u.phone_number LIKE $${queryParams.length} OR u.full_name ILIKE $${queryParams.length})`;
    }

    // Filtro por tipo (cash_in, cash_out)
    if (type && type !== 'ALL') {
      queryParams.push(type.toLowerCase());
      query += ` AND LOWER(t.type) = $${queryParams.length}`;
    }

    // Ordenar por las más recientes primero
    query += ` ORDER BY t.created_at DESC LIMIT 50`;

    const result = await pool.query(query, queryParams);

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Error al obtener historial:', error);
    res.status(500).json({ success: false, error: 'Error al consultar historial de transacciones' });
  }
});

app.post('/api/agent/register-client', verifyToken, requireRole('AGENT'), async (req, res) => {
  try {
    const { phone_number, full_name, pin } = req.body;

    if (!phone_number || !full_name || !pin) {
      return res.status(400).json({ success: false, error: "El teléfono, nombre y PIN son obligatorios" });
    }

    // Verificar si el cliente ya existe
    const existing = await pool.query('SELECT id FROM users WHERE phone_number = $1', [phone_number]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ success: false, error: "El número de teléfono ya está registrado" });
    }

    // Cifrar el PIN de forma segura con bcrypt
    const salt = await bcrypt.genSalt(10);
    const pin_hash = await bcrypt.hash(pin, salt);

    const result = await pool.query(
      'INSERT INTO users (phone_number, full_name, pin_hash, role, balance) VALUES ($1, $2, $3, \'CLIENT\', 0.00) RETURNING id, phone_number, full_name',
      [phone_number, full_name, pin_hash]
    );

    return res.json({ success: true, client: result.rows[0] });
  } catch (error) {
    console.error("ERROR AL REGISTRAR CLIENTE:", error);
    return res.status(500).json({ success: false, error: "Error interno al registrar al cliente" });
  }
});

// Obtener el saldo del agente
app.get('/api/agent/balance', verifyToken, requireRole('AGENT'), async (req, res) => {
    try {
        const agent_id = req.user.id;
        const result = await pool.query('SELECT balance FROM users WHERE id = $1', [agent_id]);

        if (result.rows.length > 0) {
            return res.json({ balance: result.rows[0].balance });
        } else {
            return res.status(404).json({ error: 'Billetera no encontrada' });
        }
    } catch (error) {
        console.error("ERROR DETALLADO EN /api/agent/balance:", error);
        return res.status(500).json({ error: "Error interno al consultar el saldo del agente" });
    }
});

// Buscar cliente por teléfono
app.get('/api/users/lookup/:phone', verifyToken, async (req, res) => {
  try {
    const { phone } = req.params;

    const result = await pool.query(
      'SELECT id, full_name, phone_number FROM users WHERE phone_number = $1',
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Cliente no encontrado. Verifica el número de teléfono.' 
      });
    }

    return res.json({
      success: true,
      client: {
        id: result.rows[0].id,
        name: result.rows[0].full_name,
        phone: result.rows[0].phone_number
      }
    });
  } catch (error) {
    console.error("ERROR AL BUSCAR CLIENTE:", error);
    return res.status(500).json({ success: false, error: "Error interno al buscar al cliente" });
  }
});


// Ruta para consultar el nombre del cliente por teléfono
app.post('/api/consult-client', verifyToken, requireRole('AGENT', 'ADMIN'), async (req, res) => {
  try {
    const { phone_number } = req.body;

    const query = 'SELECT full_name FROM users WHERE phone_number = $1';
    const result = await pool.query(query, [phone_number]);

    if (result.rows.length > 0) {
      res.json({ client_name: result.rows[0].full_name });
    } else {
      res.status(404).json({ error: 'Cliente no encontrado' });
    }
  } catch (error) {
    console.error('Error al consultar cliente:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Ruta para realizar el Corte de Caja (Cierre de Turno)
// Ruta para realizar el Corte de Caja (Cierre de Turno Dinámico)
app.post('/api/cierre-caja', verifyToken, requireRole('AGENT'), async (req, res) => {
    const agentId = req.user.id;
    const { efectivo_fisico, fondo_inicial = 0 } = req.body;

    if (efectivo_fisico === undefined || efectivo_fisico === null || isNaN(parseFloat(efectivo_fisico))) {
        return res.status(400).json({ success: false, error: 'Ingresa una cantidad válida de efectivo físico.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Bloquear fila del agente para evitar cortes concurrentes duplicados
        const agentLock = await client.query(
            'SELECT id FROM users WHERE id::text = $1::text FOR UPDATE',
            [String(agentId)]
        );
        if (agentLock.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Agente no encontrado.' });
        }

        // 1. Obtener la fecha del último corte registrado de este agente
        const ultimoCorteResult = await client.query(
            'SELECT created_at FROM caja_cortes WHERE agent_id::text = $1::text ORDER BY created_at DESC LIMIT 1',
            [String(agentId)]
        );

        const fechaUltimoCorte = ultimoCorteResult.rows.length > 0
            ? ultimoCorteResult.rows[0].created_at
            : '1970-01-01 00:00:00';

        // 2. Calcular Total Cash-In desde el último corte
        const cashInQuery = `
            SELECT COALESCE(SUM(amount), 0) AS total_cash_in
            FROM transactions
            WHERE agent_id::text = $1::text
              AND LOWER(type) IN ('cash_in', 'cash-in', 'deposit', 'deposito', 'ingreso')
              AND created_at > $2
        `;
        const cashInResult = await client.query(cashInQuery, [String(agentId), fechaUltimoCorte]);
        const totalCashIn = round2(parseFloat(cashInResult.rows[0].total_cash_in || 0));

        // 3. Calcular Total Cash-Out desde el último corte
        const cashOutQuery = `
            SELECT COALESCE(SUM(amount), 0) AS total_cash_out
            FROM transactions
            WHERE agent_id::text = $1::text
              AND LOWER(type) IN ('cash_out', 'cash-out', 'withdrawal', 'retiro')
              AND created_at > $2
        `;
        const cashOutResult = await client.query(cashOutQuery, [String(agentId), fechaUltimoCorte]);
        const totalCashOut = round2(parseFloat(cashOutResult.rows[0].total_cash_out || 0));

        // 4. Cálculos matemáticos del corte
        const fondoInicialNum = round2(parseFloat(fondo_inicial) || 0);
        const efectivoEsperado = round2(fondoInicialNum + totalCashIn - totalCashOut);
        const efectivoFisicoNum = round2(parseFloat(efectivo_fisico));
        const diferencia = round2(efectivoFisicoNum - efectivoEsperado);

        let estado = 'Cuadrado';
        if (diferencia > 0) estado = `Sobrante (+Q${diferencia.toFixed(2)})`;
        if (diferencia < 0) estado = `Faltante (-Q${Math.abs(diferencia).toFixed(2)})`;

        // 5. Guardar este corte de caja en la base de datos
        await client.query(
            `INSERT INTO caja_cortes 
             (agent_id, fondo_inicial, total_cash_in, total_cash_out, efectivo_esperado, efectivo_fisico, diferencia, estado)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [agentId, fondoInicialNum, totalCashIn, totalCashOut, efectivoEsperado, efectivoFisicoNum, diferencia, estado]
        );

        await client.query('COMMIT');

        return res.json({
            success: true,
            fondo_inicial: fondoInicialNum.toFixed(2),
            total_cash_in: totalCashIn.toFixed(2),
            total_cash_out: totalCashOut.toFixed(2),
            efectivo_esperado: efectivoEsperado.toFixed(2),
            efectivo_fisico: efectivoFisicoNum.toFixed(2),
            diferencia: diferencia.toFixed(2),
            estado: estado
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (cierre-caja):', rollbackErr);
        }
        console.error('Error en el corte de caja:', error);
        return res.status(500).json({ success: false, error: 'Error interno al procesar el corte de caja' });
    } finally {
        client.release();
    }
});

// ==========================================
// ENDPOINT: POST /api/client/request-withdrawal (Cliente solicita retiro con código en Agente - Máx Q2,000)
// ==========================================
app.post('/api/client/request-withdrawal', verifyToken, async (req, res) => {
    const clientId = req.user.id;
    const rawAmount = parseFloat(req.body.amount);
    const withdrawAmount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;

    if (Number.isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ success: false, error: "Monto inválido para el retiro" });
    }

    // 🛡️ Tope unificado de Q2,000.00 en Punto Agente para Tier 1 y Tier 2
    const MAX_RETIRO_AGENTE = 2000.00;
    if (withdrawAmount > MAX_RETIRO_AGENTE) {
        return res.status(400).json({
            success: false,
            error: `El límite máximo para retiro en efectivo en Punto Agente es de Q${MAX_RETIRO_AGENTE.toFixed(2)} por transacción. Si eres Cliente Tier 2 y deseas retirar un monto mayor, utiliza Transferencia Bancaria (ACH).`
        });
    }

    let comisiones;
    try {
        comisiones = calcularYDividirComision(withdrawAmount);
    } catch (err) {
        return res.status(400).json({ success: false, error: err.message });
    }

    const totalRequerido = round2(withdrawAmount + comisiones.comisionTotal);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Verificar saldo del cliente (incluyendo comisión)
        const userCheck = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [clientId]);
        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        const currentBalance = round2(parseFloat(userCheck.rows[0].balance || 0));

        if (currentBalance < totalRequerido) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Necesitas Q${totalRequerido.toFixed(2)} (incluye Q${comisiones.comisionTotal.toFixed(2)} de comisión).`
            });
        }

        // 2. Generar un código aleatorio de 6 dígitos
        const withdrawalCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // Expira en 30 minutos

        // 3. Guardar el código en la tabla withdrawal_codes
        await client.query(
            `INSERT INTO withdrawal_codes (code, client_id, amount, status, expires_at) 
             VALUES ($1, $2, $3, 'PENDING', $4)`,
            [withdrawalCode, clientId, withdrawAmount, expiresAt]
        );

        await client.query('COMMIT');

        return res.json({
            success: true,
            code: withdrawalCode,
            commission: comisiones.comisionTotal,
            total_deducted_on_cashout: totalRequerido,
            message: "Código de retiro generado exitosamente (Válido por 30 min)."
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error al generar código de retiro:", error);
        return res.status(500).json({ success: false, error: "Error interno al procesar la solicitud" });
    } finally {
        client.release();
    }
});

// ==========================================
// ENDPOINT: POST /api/client/withdraw-bank (Retiro Bancario ACH exclusivo Clientes Tier 2)
// ==========================================
app.post('/api/client/withdraw-bank', verifyToken, requireRole('CLIENT'), validarLimitesAML, async (req, res) => {
    const clientId = String(req.user.id);
    const { amount, bank_name, account_number, account_type } = req.body;

    const rawAmount = parseFloat(amount);
    const withdrawAmount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;

    if (Number.isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Monto de retiro inválido.' });
    }

    if (!bank_name || !String(bank_name).trim() || !account_number || !String(account_number).trim()) {
        return res.status(400).json({ success: false, error: 'Proporciona el banco y el número de cuenta de destino.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Bloquear fila del cliente y verificar Tier 2
        const userRes = await client.query(
            'SELECT id, balance, tier, full_name FROM users WHERE id::text = $1::text FOR UPDATE',
            [clientId]
        );

        if (userRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }

        const user = userRes.rows[0];
        const userTier = Number(user.tier || 1);

        if (userTier !== 2) {
            await client.query('ROLLBACK');
            return res.status(403).json({
                success: false,
                error: 'Los retiros por Transferencia Bancaria (ACH) están disponibles únicamente para clientes verificados Tier 2.'
            });
        }

        // Opcional: monto mínimo para ACH de cliente (ej. Q500.00)
        const MINIMO_ACH_CLIENT = 500.00;
        if (withdrawAmount < MINIMO_ACH_CLIENT) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `El monto mínimo para solicitar Transferencia Bancaria (ACH) es de Q${MINIMO_ACH_CLIENT.toFixed(2)}. Para montos menores, retira en efectivo en un Punto Agente.`
            });
        }

        const currentBalance = round2(parseFloat(user.balance || 0));
        if (currentBalance < withdrawAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Tu saldo disponible es de Q${currentBalance.toFixed(2)}.`
            });
        }

        // 2. Descontar saldo al cliente (y en wallets si tiene registro)
        await client.query(
            'UPDATE users SET balance = ROUND((balance - $1)::numeric, 2) WHERE id::text = $2::text',
            [withdrawAmount, clientId]
        );
        await client.query(
            'UPDATE wallets SET balance = ROUND((balance - $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
            [withdrawAmount, clientId]
        );

        // 3. Registrar la transacción pendiente para que aparezca en el panel Admin ACH
        const folioUnico = `ACH-CLI-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

        await client.query(
            `INSERT INTO transactions (client_id, amount, type, bank_name, account_number, account_type, created_at)
             VALUES ($1, $2, 'BANK-WITHDRAWAL-PENDING', $3, $4, $5, NOW())`,
            [
                clientId,
                withdrawAmount,
                String(bank_name).trim(),
                String(account_number).trim(),
                String(account_type || 'Monetaria').trim()
            ]
        );

        await client.query('COMMIT');

        console.log(`📌 NUEVO RETIRO BANCARIO CLIENTE TIER 2: ${user.full_name} solicita Q${withdrawAmount} a ${bank_name} No. ${account_number}`);

        return res.json({
            success: true,
            folio: folioUnico,
            amount: withdrawAmount,
            detalles_cuenta: {
                banco: String(bank_name).trim(),
                cuenta: String(account_number).trim(),
                tipo: String(account_type || 'Monetaria').trim()
            },
            message: 'Solicitud de transferencia bancaria (ACH) enviada con éxito. Se depositará a tu cuenta en horario hábil.'
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (client withdraw-bank):', rollbackErr);
        }
        console.error('Error al procesar retiro bancario de cliente Tier 2:', error);
        return res.status(500).json({ success: false, error: 'Error interno al procesar la solicitud bancaria.' });
    } finally {
        client.release();
    }
});

// ========================================== 
// ENDPOINT: POST /api/client/lookup-transaction (Consultar transacción exacta por Folio/ID)
// ==========================================
app.post('/api/client/lookup-transaction', verifyToken, async (req, res) => {
    const { folio } = req.body;
    const currentUserRole = String(req.user.role || '').toUpperCase();

    if (!folio || !folio.trim()) {
        return res.status(400).json({ success: false, error: "Ingresa un código de validación o folio." });
    }

    const cleanFolio = folio.trim();
    const matches = cleanFolio.match(/\d+/g);
    const searchId = matches ? matches[matches.length - 1] : null;

    if (!searchId) {
        return res.status(400).json({ success: false, error: "El formato del folio no es válido." });
    }

    try {
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type,
                t.created_at,
                t.client_id,
                t.merchant_id,
                t.agent_id,
                COALESCE(m_owner.full_name, merchant_user.full_name, agent_user.full_name, 'Comercio Local') AS merchant_name,
                COALESCE(agent_user.full_name, 'Agente Autorizado') AS agent_name,
                agent_user.full_name AS agent_sender_name,       -- 👈 Emisor específico para P2P
                agent_user.phone_number AS agent_sender_phone,
                client_user.full_name AS client_user_name,       -- 👈 Cliente/Pagador real
                client_user.phone_number AS client_phone,
                receiver.full_name AS receiver_name,
                receiver.phone_number AS receiver_phone
            FROM transactions t
            LEFT JOIN merchants m ON t.merchant_id::text = m.id::text
            LEFT JOIN users m_owner ON m.owner_user_id::text = m_owner.id::text
            LEFT JOIN users merchant_user ON t.merchant_id::text = merchant_user.id::text
            LEFT JOIN users agent_user ON t.agent_id::text = agent_user.id::text
            LEFT JOIN users client_user ON t.client_id::text = client_user.id::text
            LEFT JOIN users receiver ON t.client_id::text = receiver.id::text
            WHERE t.id::text = $1::text OR ('TRX-' || t.id::text) ILIKE $1
        `;

        const result = await pool.query(query, [searchId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: "No se encontró ninguna transacción con ese número de folio." });
        }

        const tx = result.rows[0];
        let rawType = String(tx.type).toUpperCase();
        let formatType = 'Transferencia P2P';

        if (rawType.includes('MERCHANT') || rawType.includes('COMERCIO')) {
            if (currentUserRole === 'CLIENT') {
                formatType = 'Pago a Comercio';
            } else {
                formatType = 'Venta Recibida';
            }
        } else if (rawType.includes('REFUND')) {
            formatType = 'Devolución / Reembolso';
        } else if (rawType.includes('IN') && !rawType.includes('TRANSFER')) {
            formatType = 'Depósito (Cash-In)';
        } else if (rawType.includes('OUT') && !rawType.includes('TRANSFER')) {
            formatType = 'Retiro (Cash-Out)';
        }

        // 🛡️ Lógica separada y limpia según el tipo de transacción
        let finalClientName = 'Cliente Tiolito';
        let finalClientPhone = 'N/A';
        let finalSenderName = 'Emisor';
        let finalSenderPhone = 'N/A';
        let finalReceiverName = 'Receptor';
        let finalReceiverPhone = 'N/A';
        let merchantNameFinal = tx.merchant_name || 'Comercio Local';

        if (rawType.includes('MERCHANT') || rawType.includes('COMERCIO')) {
            // Pagos a Comercio: El cliente pagador viene de client_user_name
            finalClientName = tx.client_user_name || 'Cliente Tiolito';
            finalClientPhone = tx.client_phone || 'N/A';
            finalSenderName = finalClientName;
            finalSenderPhone = finalClientPhone;
            finalReceiverName = merchantNameFinal;
        } else {
            // Transferencias P2P: El emisor viene de agent_sender_name y el receptor de client_user_name
            finalSenderName = tx.agent_sender_name || 'Emisor';
            finalSenderPhone = tx.agent_sender_phone || 'N/A';
            finalClientName = tx.client_user_name || 'Receptor';
            finalClientPhone = tx.client_phone || 'N/A';
            finalReceiverName = tx.client_user_name || 'Receptor';
            finalReceiverPhone = tx.client_phone || 'N/A';
        }

        res.json({
            success: true,
            transaction: {
                transactionId: `TRX-${tx.id}`,
                type: formatType,
                agentName: tx.agent_name || 'Agente Autorizado',
                clientName: finalClientName,
                clientPhone: finalClientPhone,
                merchantName: merchantNameFinal,
                senderName: finalSenderName,
                senderPhone: finalSenderPhone,
                receiverName: finalReceiverName,
                receiverPhone: finalReceiverPhone,
                amount: tx.amount,
                date: new Date(tx.created_at).toLocaleString()
            }
        });

    } catch (error) {
        console.error("Error al buscar transacción por código:", error);
        res.status(500).json({ success: false, error: "Error al consultar la transacción" });
    }
});

// ==========================================
// CONFIGURACIÓN DE LÍMITES AML/PLD (GUATEMALA)
// ==========================================
const LIMITE_POR_TRANSACCION_TIER1 = 2000.00;   
const LIMITE_DIARIO_ACUMULADO_TIER1 = 5000.00;  
const LIMITE_MENSUAL_ACUMULADO_TIER1 = 25000.00; 

const LIMITE_POR_TRANSACCION_TIER2 = 10000.00;   
const LIMITE_DIARIO_ACUMULADO_TIER2 = 25000.00;  
const LIMITE_MENSUAL_ACUMULADO_TIER2 = 100000.00; 

// Middleware para validar límites de prevención de lavado de dinero y riesgo con soporte para Tier 1 y Tier 2
async function validarLimitesAML(req, res, next) {
  try {
    let clientId = req.user?.id;
    let userTier = 1; // Por defecto asumimos Tier 1 (Estándar)

    // 1. Si la petición viene autenticada por token, obtenemos ID y Tier del usuario
    if (clientId) {
      const userRes = await pool.query('SELECT id, tier FROM users WHERE id = $1', [clientId]);
      if (userRes.rows.length > 0) {
        userTier = Number(userRes.rows[0].tier || 1);
      }
    } else {
      // 2. Si no hay token (ej. en Cash-In o Cash-Out), buscamos por el teléfono en el body
      const phone_number = req.body.phone_number || req.body.client_phone || req.body.telefono || req.body.phone;
      let userRes = await pool.query('SELECT id, tier FROM users WHERE phone_number = $1', [phone_number]);
      if (userRes.rows.length === 0) {
        userRes = await pool.query('SELECT id, tier FROM users WHERE telefono = $1', [phone_number]);
      }

      if (userRes.rows.length === 0) {
        return res.status(404).json({ error: 'Cliente no registrado en el sistema' });
      }
      clientId = userRes.rows[0].id;
      userTier = Number(userRes.rows[0].tier || 1);
    }

    const amount = req.body.amount ?? req.body.monto ?? req.body.withdrawAmount ?? 0;
    const montoNum = parseFloat(amount);

    // 3. Validar que el monto ingresado sea un número positivo
    if (isNaN(montoNum) || montoNum <= 0) {
      return res.status(400).json({ error: 'Ingresa un monto válido mayor a 0.' });
    }

    // 4. Seleccionar los límites vigentes según el Tier del cliente
    const limitePorTransaccion = (userTier === 2) ? LIMITE_POR_TRANSACCION_TIER2 : LIMITE_POR_TRANSACCION_TIER1;
    const limiteDiarioAcumulado = (userTier === 2) ? LIMITE_DIARIO_ACUMULADO_TIER2 : LIMITE_DIARIO_ACUMULADO_TIER1;
    const limiteMensualAcumulado = (userTier === 2) ? LIMITE_MENSUAL_ACUMULADO_TIER2 : LIMITE_MENSUAL_ACUMULADO_TIER1;

    // 5. Validar límite individual por transacción
    if (montoNum > limitePorTransaccion) {
      const limiteFmt = limitePorTransaccion.toFixed(2);
      return res.status(400).json({
        error: `La operación excede el límite permitido de Q${limiteFmt} por transacción.`
      });
    }

    // 6. Consultar acumulado diario y mensual de forma segura usando el clientId
    const queryAcumulados = `
      SELECT 
        COALESCE(SUM(CASE WHEN (created_at AT TIME ZONE 'America/Guatemala')::date = (NOW() AT TIME ZONE 'America/Guatemala')::date THEN amount ELSE 0 END), 0) AS total_hoy,
        COALESCE(SUM(CASE WHEN EXTRACT(MONTH FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(MONTH FROM (NOW() AT TIME ZONE 'America/Guatemala')) AND EXTRACT(YEAR FROM (created_at AT TIME ZONE 'America/Guatemala')) = EXTRACT(YEAR FROM (NOW() AT TIME ZONE 'America/Guatemala')) THEN amount ELSE 0 END), 0) AS total_mes
      FROM transactions 
      WHERE (
  client_id::text = $1::text
  OR (agent_id::text = $1::text AND UPPER(type) LIKE '%TRANSFER%')) `;

    const result = await pool.query(queryAcumulados, [clientId]);
    const row = result.rows[0] || { total_hoy: 0, total_mes: 0 };
    const totalHoy = parseFloat(row.total_hoy) || 0;
    const totalMes = parseFloat(row.total_mes) || 0;

    // 7. Validar límite diario acumulado
    if (totalHoy + montoNum > limiteDiarioAcumulado) {
      const diarioFmt = limiteDiarioAcumulado.toFixed(2);
      const hoyFmt = totalHoy.toFixed(2);
      return res.status(400).json({
        error: `La operación supera el límite diario permitido (Q${diarioFmt}). Acumulado hoy: Q${hoyFmt}.`
      });
    }

    // 8. Validar límite mensual acumulado
    if (totalMes + montoNum > limiteMensualAcumulado) {
      const mesFmt = limiteMensualAcumulado.toFixed(2);
      const totalMesFmt = totalMes.toFixed(2);
      return res.status(400).json({
        error: `La operación supera el límite mensual permitido (Q${mesFmt}). Acumulado este mes: Q${totalMesFmt}.`
      });
    }

    next();
  } catch (error) {
    console.error('Error al validar límites AML:', error);
    res.status(500).json({ error: 'Error interno al verificar los límites de seguridad' });
  }
} 

// ==========================================
// ENDPOINTS PARA EL ROL DE COMERCIO (MERCHANT)
// ==========================================

// 1. Obtener saldo acumulado del comercio
app.get('/api/merchant/balance', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    try {
        const merchantId = req.user.id;
        const result = await pool.query('SELECT balance FROM users WHERE id = $1', [merchantId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Comercio no encontrado' });
        }
        
        res.json({ success: true, balance: result.rows[0].balance || '0.00' });
    } catch (error) {
        console.error("Error al obtener saldo del comercio:", error);
        res.status(500).json({ success: false, error: "Error interno al obtener el saldo del comercio" });
    }
});

// ==========================================
// 2. Generar orden de cobro (Código / QR dinámico en PostgreSQL)
// ==========================================
app.post('/api/merchant/generate-charge', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    try {
        const rawAmount = parseFloat(req.body.amount);
        const amount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;
        const merchantId = String(req.user.id);

        if (Number.isNaN(amount) || amount <= 0) {
            return res.status(400).json({ success: false, error: 'Ingresa un monto válido para cobrar' });
        }

        const chargeCode = 'CHG-' + Math.floor(100000 + Math.random() * 900000);
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // Expira en 5 minutos

        await pool.query(
            `INSERT INTO charge_orders (code, merchant_id, amount, status, expires_at)
             VALUES ($1, $2, $3, 'PENDING', $4)`,
            [chargeCode, merchantId, amount, expiresAt]
        );

        return res.json({
            success: true,
            charge_code: chargeCode,
            expires_at: expiresAt,
            message: "Orden de cobro generada exitosamente (Expira en 5 minutos)"
        });
    } catch (error) {
        console.error("Error al generar orden de cobro:", error);
        return res.status(500).json({ success: false, error: "Error interno al generar una orden de cobro" });
    }
});

const hasMerchantRole = (role) => {
  const normalized = String(role || '').trim().toUpperCase();
  return (
    normalized === 'MERCHANT' ||
    normalized === 'COMERCIO' ||
    normalized.includes('MERCHANT') ||
    normalized.includes('COMERCIO')
  );
};

// ==========================================
// ENDPOINT: GET /api/merchant/daily-report (UUID, Auth por Token y TZ Guatemala)
// ==========================================
app.get('/api/merchant/daily-report', verifyToken, async (req, res) => {
  try {
    if (!hasMerchantRole(req.user?.role)) {
      return res.status(403).json({
        success: false,
        error: `Acceso denegado para el rol: ${req.user?.role || 'desconocido'}`
      });
    }

    const merchantId = String(req.user?.id || '').trim();

    if (!merchantId) {
      return res.status(400).json({
        success: false,
        message: "ID de comercio no encontrado en el token"
      });
    }

    const filterClause = `
      (t.merchant_id::text = $1::text OR t.agent_id::text = $1::text)
      AND UPPER(COALESCE(t.type, '')) IN ('MERCHANT-PAYMENT', 'MERCHANT_PAYMENT')
      AND (t.created_at AT TIME ZONE 'America/Guatemala')::date =
          (NOW() AT TIME ZONE 'America/Guatemala')::date
    `;

    const summaryQuery = `
      SELECT 
        COALESCE(SUM(t.amount), 0) AS total_sales, 
        COUNT(*) AS total_transactions
      FROM transactions t
      WHERE ${filterClause};
    `;

    const txQuery = `
      SELECT 
        t.*,
        COALESCE(u.full_name, 'Cliente Tiolito') AS client_name,
        COALESCE(u.phone_number, 'N/A') AS client_phone
      FROM transactions t
      LEFT JOIN users u ON t.client_id::text = u.id::text
      WHERE ${filterClause}
      ORDER BY t.created_at DESC;
    `;

    const [summaryRes, txRes] = await Promise.all([
      pool.query(summaryQuery, [merchantId]),
      pool.query(txQuery, [merchantId])
    ]);

    const rawSummary = summaryRes.rows[0] || { total_sales: 0, total_transactions: 0 };
    const totalSales = Math.round((Number(rawSummary.total_sales || 0) + Number.EPSILON) * 100) / 100;
    const totalTransactions = parseInt(rawSummary.total_transactions || 0, 10);

    return res.json({
      success: true,
      summary: {
        total_sales: totalSales,
        total_transactions: totalTransactions
      },
      transactions: txRes.rows
    });

  } catch (error) {
    console.error("Error al generar el corte del comercio:", error);
    return res.status(500).json({
      success: false,
      message: "Error al generar el reporte"
    });
  }
});

// ==========================================
// 3. Historial detallado del comercio (Ventas y Retiros)
// ==========================================
app.get('/api/merchant/transactions', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    try {
        const merchantId = req.user.id;
        
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type,
                t.created_at, 
                COALESCE(u.full_name, 'Cliente Tiolito') AS client_name,
                COALESCE(u.phone_number, 'N/A') AS client_phone,
                COALESCE(m.full_name, 'Comercio') AS merchant_name
            FROM transactions t
            LEFT JOIN users u ON t.client_id::text = u.id::text
            LEFT JOIN users m ON t.merchant_id::text = m.id::text OR t.agent_id::text = m.id::text
            WHERE (t.merchant_id::text = $1::text OR t.agent_id::text = $1::text OR t.client_id::text = $1::text) 
              AND UPPER(t.type) IN (
                  'MERCHANT-PAYMENT', 
                  'REFUND', 
                  'MERCHANT_PAYMENT', 
                  'AGENT-WITHDRAWAL-PENDING', 
                  'BANK-WITHDRAWAL-PENDING'
              )
            ORDER BY t.created_at DESC 
            LIMIT 50   
        `;

        const result = await pool.query(query, [merchantId]);

        res.json({ 
            success: true, 
            transactions: result.rows 
        });

    } catch (error) {
        console.error("Error al cargar transacciones detalladas del comercio:", error);
        res.status(500).json({ success: false, error: "Error interno al cargar las transacciones del comercio" });
    }
});

// ==========================================
// ENDPOINT: POST /api/client/pay-merchant (Con orden en PostgreSQL y bloqueo FOR UPDATE)
// ==========================================
app.post('/api/client/pay-merchant', verifyToken, async (req, res) => {
    const clientId = String(req.user.id);
    const chargeCode = String(req.body.charge_code || '').trim();

    if (!chargeCode) {
        return res.status(400).json({ success: false, error: 'Ingresa o escanea un código de cobro válido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Buscar y bloquear la orden de cobro en PostgreSQL
        const chargeRes = await client.query(
            `SELECT id, code, merchant_id, amount, status, expires_at
             FROM charge_orders
             WHERE code = $1
             FOR UPDATE`,
            [chargeCode]
        );

        if (chargeRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: 'El código de cobro ya fue utilizado o es inválido.' });
        }

        const chargeOrder = chargeRes.rows[0];

        if (String(chargeOrder.status || '').toUpperCase() !== 'PENDING') {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: 'El código de cobro ya fue utilizado o no está disponible.' });
        }

        // 🕒 2. VALIDAR EXPIRACIÓN (5 Minutos)
        if (new Date(chargeOrder.expires_at) <= new Date()) {
            await client.query(
                `UPDATE charge_orders
                 SET status = 'EXPIRED'
                 WHERE id = $1 AND status = 'PENDING'`,
                [chargeOrder.id]
            );
            await client.query('COMMIT');
            return res.status(400).json({ success: false, error: 'El código de cobro ha expirado (más de 5 minutos).' });
        }

        const amountToPay = round2(parseFloat(chargeOrder.amount)); // Monto bruto que paga el cliente
        const merchantUserId = String(chargeOrder.merchant_id);

        if (clientId === merchantUserId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: 'No puedes pagar tu propia orden de cobro.' });
        }

        // 3. Bloquear en orden determinista cliente y comercio para evitar deadlocks
        const accountIds = [clientId, merchantUserId].sort((a, b) => a.localeCompare(b));
        const lockedUsers = new Map();

        for (const accId of accountIds) {
            const uRes = await client.query(
                'SELECT id, full_name, phone_number, balance, merchant_type, tier FROM users WHERE id::text = $1::text FOR UPDATE',
                [accId]
            );
            if (uRes.rows.length > 0) {
                lockedUsers.set(accId, uRes.rows[0]);
            }
        }

        const merchantData = lockedUsers.get(merchantUserId);
        if (!merchantData) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Comercio receptor no encontrado.' });
        }

        const clientData = lockedUsers.get(clientId);
        if (!clientData) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }

        const merchantName = merchantData.full_name || 'Comercio Local';

        // Detectar tipo de comercio (soporta 'merchant_type' o 'tier')
        const merchantType = String(merchantData.merchant_type || merchantData.tier || 'small').toLowerCase();

        // 🛡️ 4. APLICAR LÍMITES SEGÚN EL TIPO DE COMERCIO
        let limiteMaxPerTx = 2500.00;
        let limiteMaxDaily = 10000.00;
        let tasaComision = 0.020; // 2.0% por defecto para pequeños

        if (merchantType === 'large' || merchantType === 'grande') {
            limiteMaxPerTx = 10000.00; // Límite mayor para grandes
            limiteMaxDaily = 50000.00; // Límite diario mayor para grandes
            tasaComision = 0.025;      // 2.5% estándar para grandes
        }

        // Validar límite por transacción individual
        if (amountToPay > limiteMaxPerTx) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `El monto excede el límite permitido para este tipo de comercio (Máx. Q${limiteMaxPerTx.toFixed(2)}).`
            });
        }

        // Consultar acumulado diario del comercio en transacciones de hoy (Convertido a texto para evitar errores)
        const ventasHoyRes = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS total_hoy
             FROM transactions
             WHERE (merchant_id::text = $1::text OR agent_id::text = $1::text)
               AND UPPER(type) IN ('MERCHANT-PAYMENT', 'MERCHANT_PAYMENT')
               AND (created_at AT TIME ZONE 'America/Guatemala')::date = (NOW() AT TIME ZONE 'America/Guatemala')::date`,
            [merchantUserId]
        );
        const totalVentasHoy = round2(parseFloat(ventasHoyRes.rows[0].total_hoy || 0));

        if (round2(totalVentasHoy + amountToPay) > limiteMaxDaily) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `El comercio ha alcanzado su límite diario acumulado permitido (Máx. Q${limiteMaxDaily.toFixed(2)}).`
            });
        }

        // 5. Validar saldo del cliente pagador
        const clientBalance = round2(parseFloat(clientData.balance || 0));
        if (clientBalance < amountToPay) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Tienes Q${clientBalance.toFixed(2)} y necesitas Q${amountToPay.toFixed(2)}.`
            });
        }

        // 🚀 6. CÁLCULO DINÁMICO DE COMISIONES
        const comisionTiolito = round2(amountToPay * tasaComision);
        const montoNetoComercio = round2(amountToPay - comisionTiolito);
        const newClientBalance = round2(clientBalance - amountToPay);
        const newMerchantBalance = round2(parseFloat(merchantData.balance || 0) + montoNetoComercio);

        // 7. Descontar el monto total al cliente
        await client.query(
            'UPDATE users SET balance = $1 WHERE id::text = $2::text',
            [newClientBalance, clientId]
        );

        // 8. Acreditar el monto NETO al comercio
        await client.query(
            'UPDATE users SET balance = $1 WHERE id::text = $2::text',
            [newMerchantBalance, merchantUserId]
        );
        await client.query(
            'UPDATE wallets SET balance = ROUND((balance + $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
            [montoNetoComercio, merchantUserId]
        );

        // 9. Acreditar el 100% de la comisión a Tiolito Admin automáticamente
        if (comisionTiolito > 0) {
            const adminRes = await client.query(
                "SELECT id FROM users WHERE UPPER(role) = 'ADMIN' OR phone_number = '00000000' ORDER BY id ASC LIMIT 1 FOR UPDATE"
            );
            if (adminRes.rows.length > 0) {
                const adminId = String(adminRes.rows[0].id);
                await client.query(
                    'UPDATE users SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2) WHERE id::text = $2::text',
                    [comisionTiolito, adminId]
                );
                await client.query(
                    'UPDATE wallets SET balance = ROUND((balance + $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
                    [comisionTiolito, adminId]
                );
            }
        }

        // 10. Registrar la transacción en la base de datos y marcar la orden como PAID
        const txResult = await client.query(
            `INSERT INTO transactions (agent_id, client_id, merchant_id, amount, type, created_at)
             VALUES ($1, $2, $3, $4, 'MERCHANT-PAYMENT', NOW())
             RETURNING id, created_at`,
            [merchantUserId, clientId, merchantUserId, amountToPay]
        );

        // 11. Registrar comisión de administración en platform_commissions
        if (comisionTiolito > 0) {
            await client.query(
                `INSERT INTO platform_commissions
                  (transaction_id, source_type, gross_amount, commission_total, agent_commission, admin_commission, created_at)
                 VALUES ($1, 'MERCHANT-PAYMENT', $2, $3, 0.00, $3, NOW())`,
                [
                    txResult.rows[0].id,
                    amountToPay,
                    comisionTiolito
                ]
            );
        }

        await client.query(
            `UPDATE charge_orders
             SET status = 'PAID', paid_by_client_id = $1, paid_at = NOW()
             WHERE id = $2`,
            [clientId, chargeOrder.id]
        );

        await client.query('COMMIT');

        io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

        const receiptPayload = {
            folio: `TRX-${txResult.rows[0].id}`,
            id: txResult.rows[0].id,
            type: 'Pago a Comercio',
            sender_name: clientData.full_name,
            senderName: clientData.full_name,
            clientName: clientData.full_name,
            full_name: clientData.full_name,
            sender_phone: clientData.phone_number,
            merchant_name: merchantName,
            merchantName: merchantName,
            amount: amountToPay,
            net_amount: montoNetoComercio,
            commission: comisionTiolito,
            merchant_type: merchantType,
            created_at: txResult.rows[0].created_at
        };

        // 12. 🚀 NOTIFICAR EN TIEMPO REAL AL COMERCIO VÍA SOCKET
        console.log(`📢 Intentando emitir 'payment_received' a la sala: merchant_${merchantUserId}`);
        io.to(`merchant_${merchantUserId}`).emit('payment_received', receiptPayload);

        // 13. Responder al cliente
        return res.json({
            success: true,
            transaction: receiptPayload
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (pay-merchant):', rollbackErr);
        }
        console.error('Error al procesar pago a comercio:', error);
        return res.status(500).json({ success: false, error: 'Error interno al procesar el pago' });
    } finally {
        client.release();
    }
});

// ==========================================
// 1. RETIRO EN PUNTO AGENTE (Enfocado en Comercios Pequeños Tier 1)
// ==========================================
app.post('/api/merchant/withdraw-agent', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    const merchantId = req.user.id;
    const { amount } = req.body;

    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Monto de retiro inválido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Obtener datos del comercio usando únicamente 'tier'
        const merchantRes = await client.query(
            'SELECT id, balance, tier FROM users WHERE id = $1 FOR UPDATE',
            [merchantId]
        );

        if (merchantRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Comercio no encontrado.' });
        }

        const merchant = merchantRes.rows[0];
        const merchantTier = Number(merchant.tier || 1);

        // 🛑 Comercios Tier 2 (grandes) se canalizan a liquidación bancaria ACH
        if (merchantTier === 2) {
            await client.query('ROLLBACK');
            return res.status(403).json({ 
                success: false, 
                error: 'Por el volumen de tu negocio, utiliza la opción de Liquidación Bancaria (ACH).' 
            });
        }

        // 🛡️ Límite por retiro individual en punto agente local
        const MAX_RETIRO_AGENTE = 2500.00;
        if (withdrawAmount > MAX_RETIRO_AGENTE) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `El límite máximo para retiro en efectivo en Punto Agente es de Q${MAX_RETIRO_AGENTE.toFixed(2)} por transacción.`
            });
        }

        // Validar saldo disponible
        const currentBalance = parseFloat(merchant.balance || 0);
        if (currentBalance < withdrawAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Tu saldo disponible es de Q${currentBalance.toFixed(2)}.`
            });
        }

        // 2. Generar código de retiro de 6 dígitos (Expira en 30 minutos)
        const withdrawalCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

        // 3. Registrar el código de retiro en withdrawal_codes
        await client.query(
            `INSERT INTO withdrawal_codes (code, client_id, amount, status, expires_at) 
             VALUES ($1, $2, $3, 'PENDING', $4)`,
            [withdrawalCode, merchantId, withdrawAmount, expiresAt]
        );

        // 🌟 4. REGISTRAR LA TRANSACCIÓN EN LA TABLA TRANSACTIONS PARA EL HISTORIAL
        await client.query(
            `INSERT INTO transactions (client_id, amount, type, created_at) 
             VALUES ($1, $2, 'AGENT-WITHDRAWAL-PENDING', NOW())`,
            [merchantId, withdrawAmount]
        );

        await client.query('COMMIT');

        return res.json({
            success: true,
            code: withdrawalCode,
            amount: withdrawAmount,
            message: 'Código de retiro generado exitosamente. Preséntalo en cualquier Punto Agente Tiolito (Válido por 30 min).'
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al generar retiro en agente:', error);
        return res.status(500).json({ success: false, error: "Error interno al generar el codigo de retiro" });
    } finally {
        client.release();
    }
});


// ==========================================
// 2. SOLICITUD DE TRANSFERENCIA BANCARIA (ACH) (Comercios Tier 1 y Tier 2)
// ==========================================
app.post('/api/merchant/withdraw-bank', verifyToken, requireRole('MERCHANT', 'COMERCIO'), async (req, res) => {
    const merchantId = req.user.id;
    const { amount, bank_name, account_number, account_type } = req.body;

    const withdrawAmount = round2(parseFloat(amount));
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Monto de retiro inválido.' });
    }

    if (!bank_name || !account_number) {
        return res.status(400).json({ success: false, error: 'Proporciona el banco y el número de cuenta de destino.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Bloquear fila del comercio y obtener datos
        const merchantRes = await client.query(
            'SELECT id, balance, tier, full_name FROM users WHERE id::text = $1::text FOR UPDATE',
            [String(merchantId)]
        );

        if (merchantRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Comercio no encontrado.' });
        }

        const merchant = merchantRes.rows[0];
        const merchantTier = Number(merchant.tier || 1);

        // Regla de negocio: Monto mínimo para ACH en Comercios Pequeños (Tier 1)
        const MINIMO_ACH_SMALL = 500.00;
        if (merchantTier === 1 && withdrawAmount < MINIMO_ACH_SMALL) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `El monto mínimo para solicitar Transferencia Bancaria en Comercios Pequeños es de Q${MINIMO_ACH_SMALL.toFixed(2)}. Para montos menores, retira en efectivo en un Punto Agente.`
            });
        }

        const currentBalance = round2(parseFloat(merchant.balance || 0));
        if (currentBalance < withdrawAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Tu saldo disponible es de Q${currentBalance.toFixed(2)}.`
            });
        }

        // 2. Descontar el monto exacto del retiro
        await client.query(
            'UPDATE users SET balance = ROUND((balance - $1)::numeric, 2) WHERE id::text = $2::text',
            [withdrawAmount, String(merchantId)]
        );

        // 3. Registrar la transacción en transactions
        const folioUnico = `ACH-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

        await client.query(
            `INSERT INTO transactions (client_id, amount, type, bank_name, account_number, account_type, created_at) 
             VALUES ($1, $2, 'BANK-WITHDRAWAL-PENDING', $3, $4, $5, NOW())`,
            [String(merchantId), withdrawAmount, bank_name, account_number, account_type || 'Monetaria']
        );

        await client.query('COMMIT');

        console.log(`📌 NUEVO RETIRO BANCARIO PENDIENTE (TIER ${merchantTier}): ${merchant.full_name} solicita Q${withdrawAmount} a ${bank_name} No. ${account_number}`);

        return res.json({
            success: true,
            folio: folioUnico,
            amount: withdrawAmount,
            detalles_cuenta: {
                banco: bank_name,
                cuenta: account_number,
                tipo: account_type || 'Monetaria'
            },
            message: 'Solicitud de liquidación bancaria enviada con éxito. Se procesará hacia tu cuenta en horas hábiles.'
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (merchant withdraw-bank):', rollbackErr);
        }
        console.error('Error al procesar retiro bancario de comercio:', error);
        return res.status(500).json({ success: false, error: 'Error interno al procesar la liquidación.' });
    } finally {
        client.release();
    }
});

// ==========================================
// RECARGA DE SALDO PARA AGENTES (SOLICITUD + APROBACIÓN ADMIN)
// ==========================================

// 1. Agente crea una solicitud de recarga tras depositar/transferir
app.post('/api/agent/balance-requests', verifyToken, requireRole('AGENT'), async (req, res) => {
  const agentId = String(req.user.id);
  const rawAmount = parseFloat(req.body.amount);
  const amount = Number.isFinite(rawAmount) ? round2(rawAmount) : NaN;
  const bankName = String(req.body.bank_name || '').trim();
  const referenceNumber = String(req.body.reference_number || '').trim();
  const notes = req.body.notes ? String(req.body.notes).trim() : null;

  if (Number.isNaN(amount) || amount <= 0) {
    return res.status(400).json({ success: false, error: 'Ingresa un monto válido mayor a Q0.00.' });
  }

  if (!bankName || !referenceNumber) {
    return res.status(400).json({ success: false, error: 'Ingresa el banco/canal y el número de boleta o referencia.' });
  }

  try {
    // Evitar reutilizar la misma referencia/boleta en solicitudes pendientes o ya aprobadas
    const dupRes = await pool.query(
      `SELECT id, status
       FROM agent_balance_requests
       WHERE UPPER(TRIM(reference_number)) = UPPER($1)
         AND UPPER(TRIM(bank_name)) = UPPER($2)
         AND status IN ('PENDING', 'APPROVED')
       LIMIT 1`,
      [referenceNumber, bankName]
    );

    if (dupRes.rows.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Ese número de boleta o referencia ya fue registrado para este banco.'
      });
    }

    const insertRes = await pool.query(
      `INSERT INTO agent_balance_requests (agent_id, amount, bank_name, reference_number, notes, status, created_at)
       VALUES ($1::uuid, $2, $3, $4, $5, 'PENDING', NOW())
       RETURNING id, agent_id, amount, bank_name, reference_number, notes, status, created_at`,
      [agentId, amount, bankName, referenceNumber, notes]
    );

    return res.status(201).json({
      success: true,
      request: insertRes.rows[0],
      message: 'Solicitud de recarga enviada. Queda pendiente de validación por administración.'
    });
  } catch (error) {
    console.error('Error al crear solicitud de recarga de agente:', error);
    return res.status(500).json({ success: false, error: 'Error interno al enviar la solicitud.' });
  }
});

// 2. Agente consulta sus solicitudes de recarga
app.get('/api/agent/balance-requests', verifyToken, requireRole('AGENT'), async (req, res) => {
  const agentId = String(req.user.id);

  try {
    const result = await pool.query(
      `SELECT id, amount, bank_name, reference_number, notes, status, admin_note, created_at, reviewed_at
       FROM agent_balance_requests
       WHERE agent_id::text = $1::text
       ORDER BY created_at DESC
       LIMIT 30`,
      [agentId]
    );

    return res.json({ success: true, requests: result.rows });
  } catch (error) {
    console.error('Error al consultar solicitudes del agente:', error);
    return res.status(500).json({ success: false, error: 'Error interno al obtener tus solicitudes.' });
  }
});

// 3. Admin lista solicitudes de recarga de agentes (por defecto PENDING)
app.get('/api/admin/balance-requests', verifyToken, requireRole('ADMIN'), async (req, res) => {
  const statusParam = String(req.query.status || 'PENDING').toUpperCase();

  try {
    let query = `
      SELECT
        r.id,
        r.agent_id,
        r.amount,
        r.bank_name,
        r.reference_number,
        r.notes,
        r.status,
        r.admin_note,
        r.created_at,
        r.reviewed_at,
        COALESCE(u.full_name, 'Agente') AS agent_name,
        COALESCE(u.phone_number, 'N/A') AS agent_phone,
        COALESCE(u.balance, 0) AS current_balance
      FROM agent_balance_requests r
      LEFT JOIN users u ON r.agent_id::text = u.id::text
    `;

    const params = [];
    if (['PENDING', 'APPROVED', 'REJECTED'].includes(statusParam)) {
      params.push(statusParam);
      query += ` WHERE UPPER(r.status) = $1`;
    }

    query += ` ORDER BY r.created_at DESC LIMIT 50`;

    const result = await pool.query(query, params);
    return res.json({ success: true, requests: result.rows });
  } catch (error) {
    console.error('Error al listar solicitudes de recarga para admin:', error);
    return res.status(500).json({ success: false, error: 'Error interno al cargar solicitudes de agentes.' });
  }
});

// ==========================================
// 4. Admin aprueba una solicitud y acredita el saldo al agente
// ==========================================
app.post('/api/admin/balance-requests/:id/approve', verifyToken, requireRole('ADMIN'), async (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  const adminId = String(req.user.id);
  const adminNote = req.body?.admin_note ? String(req.body.admin_note).trim() : null;

  if (!Number.isInteger(requestId) || requestId <= 0) {
    return res.status(400).json({ success: false, error: 'ID de solicitud inválido.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const reqRes = await client.query(
      `SELECT id, agent_id, amount, bank_name, reference_number, status
       FROM agent_balance_requests
       WHERE id = $1
       FOR UPDATE`,
      [requestId]
    );

    if (reqRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Solicitud no encontrada.' });
    }

    const reqRow = reqRes.rows[0];
    if (String(reqRow.status).toUpperCase() !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Esta solicitud ya fue procesada anteriormente.' });
    }

    const creditAmount = round2(parseFloat(reqRow.amount));
    const targetAgentId = String(reqRow.agent_id);

    // Bloquear agente antes de acreditar saldo
    const agentRes = await client.query(
      `SELECT id, balance FROM users WHERE id::text = $1::text FOR UPDATE`,
      [targetAgentId]
    );

    if (agentRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Agente asociado no encontrado.' });
    }

    await client.query(
      `UPDATE users
       SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2)
       WHERE id::text = $2::text`,
      [creditAmount, targetAgentId]
    );

    await client.query(
      `UPDATE wallets
       SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2), updated_at = NOW()
       WHERE user_id::text = $2::text`,
      [creditAmount, targetAgentId]
    );

    await client.query(
      `UPDATE agent_balance_requests
       SET status = 'APPROVED',
           admin_note = COALESCE($1, admin_note),
           reviewed_by = $2::uuid,
           reviewed_at = NOW()
       WHERE id = $3`,
      [adminNote, adminId, requestId]
    );

    await client.query('COMMIT');

    io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

    // Emitir actualización en tiempo real a la sala del agente
    const ioInstance =
      (typeof io !== 'undefined' && io) ||
      (req.app && typeof req.app.get === 'function' && req.app.get('io')) ||
      global.io;

    if (ioInstance) {
      ioInstance.to(`agent_${targetAgentId}`).emit('agent_balance_request_updated', {
        requestId,
        status: 'APPROVED',
        amount: creditAmount
      });
    }

    return res.json({
      success: true,
      message: `Recarga de Q${creditAmount.toFixed(2)} aprobada y acreditada al agente.`
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rbErr) {
      console.error('Error en ROLLBACK (approve balance request):', rbErr);
    }
    console.error('Error al aprobar solicitud de recarga:', error);
    return res.status(500).json({ success: false, error: 'Error interno al aprobar la recarga.' });
  } finally {
    client.release();
  }
});

// ==========================================
// 5. Admin rechaza una solicitud sin modificar saldos
// ==========================================
app.post('/api/admin/balance-requests/:id/reject', verifyToken, requireRole('ADMIN'), async (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  const adminId = String(req.user.id);
  const adminNote = req.body?.admin_note ? String(req.body.admin_note).trim() : 'Comprobante no verificado';

  if (!Number.isInteger(requestId) || requestId <= 0) {
    return res.status(400).json({ success: false, error: 'ID de solicitud inválido.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const reqRes = await client.query(
      `SELECT id, agent_id, amount, status
       FROM agent_balance_requests
       WHERE id = $1
       FOR UPDATE`,
      [requestId]
    );

    if (reqRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Solicitud no encontrada.' });
    }

    const reqRow = reqRes.rows[0];
    if (String(reqRow.status).toUpperCase() !== 'PENDING') {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Esta solicitud ya fue procesada anteriormente.' });
    }

    const targetAgentId = String(reqRow.agent_id);

    await client.query(
      `UPDATE agent_balance_requests
       SET status = 'REJECTED',
           admin_note = $1,
           reviewed_by = $2::uuid,
           reviewed_at = NOW()
       WHERE id = $3`,
      [adminNote, adminId, requestId]
    );

    await client.query('COMMIT');

    // Emitir actualización en tiempo real a la sala del agente
    const ioInstance =
      (typeof io !== 'undefined' && io) ||
      (req.app && typeof req.app.get === 'function' && req.app.get('io')) ||
      global.io;

    if (ioInstance) {
      ioInstance.to(`agent_${targetAgentId}`).emit('agent_balance_request_updated', {
        requestId,
        status: 'REJECTED',
        admin_note: adminNote
      });
    }

    return res.json({
      success: true,
      message: 'Solicitud de recarga rechazada.'
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rbErr) {
      console.error('Error en ROLLBACK (reject balance request):', rbErr);
    }
    console.error('Error al rechazar solicitud de recarga:', error);
    return res.status(500).json({ success: false, error: 'Error interno al rechazar la solicitud.' });
  } finally {
    client.release();
  }
});

// ==========================================
// Endpoint para que el Admin vea las solicitudes ACH pendientes (Comercios y Agentes)
// ==========================================
app.get('/api/admin/bank-withdrawals', verifyToken, requireRole('ADMIN'), async (req, res) => {
    try {
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type,
                t.created_at, 
                t.bank_name,
                t.account_number,
                t.account_type,
                COALESCE(u.full_name, 'Usuario') AS merchant_name,
                COALESCE(u.phone_number, 'N/A') AS merchant_phone,
                u.role AS user_role
            FROM transactions t
            LEFT JOIN users u ON t.merchant_id::text = u.id::text OR t.client_id::text = u.id::text
            WHERE UPPER(t.type) IN ('BANK-WITHDRAWAL-PENDING', 'AGENT-BANK-WITHDRAWAL-PENDING')
            ORDER BY t.created_at DESC
        `;

        const result = await pool.query(query);

        res.json({ 
            success: true, 
            withdrawals: result.rows 
        });

    } catch (error) {
        console.error("Error al obtener solicitudes ACH:", error);
        res.status(500).json({ success: false, error: "Error interno al obtener las solicitudes ACH" });
    }
});

// ==========================================
// Endpoint para que el Admin marque una liquidación ACH como completada (Comercios y Agentes)
// ==========================================
app.post('/api/admin/complete-bank-withdrawal', verifyToken, requireRole('ADMIN'), async (req, res) => {
    const { transaction_id } = req.body;

    if (!transaction_id) {
        return res.status(400).json({ success: false, error: 'ID de transacción requerido.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Bloquear la transacción pendiente para evitar doble procesamiento
        const txCheck = await client.query(
            `SELECT id, type FROM transactions
             WHERE id::text = $1::text
             FOR UPDATE`,
            [String(transaction_id)]
        );

        if (txCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Transacción no encontrada.' });
        }

        const currentType = String(txCheck.rows[0].type || '').toUpperCase();
        if (!['BANK-WITHDRAWAL-PENDING', 'AGENT-BANK-WITHDRAWAL-PENDING'].includes(currentType)) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: 'La transacción ya fue procesada o no es un retiro pendiente.' });
        }

        await client.query(
            `UPDATE transactions 
             SET type = 'BANK-WITHDRAWAL-COMPLETED' 
             WHERE id::text = $1::text`,
            [String(transaction_id)]
        );

        await client.query('COMMIT');

        io.to('admin_room').emit('financial_overview_updated', {
  updated_at: new Date()
});

        return res.json({
            success: true,
            message: 'Liquidación marcada como completada con éxito.'
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (complete-bank-withdrawal):', rollbackErr);
        }
        console.error("Error al completar liquidación ACH:", error);
        return res.status(500).json({ success: false, error: 'Error interno al completar la liquidación.' });
    } finally {
        client.release();
    }
});

// ==========================================
// Endpoint para que el Admin vea el Historial de Pagos ACH Completados (Comercios y Agentes)
// ==========================================
app.get('/api/admin/bank-withdrawals-history', verifyToken, requireRole('ADMIN'), async (req, res) => {
    try {
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type,
                t.created_at, 
                t.bank_name,
                t.account_number,
                t.account_type,
                COALESCE(u.full_name, 'Usuario') AS merchant_name,
                COALESCE(u.phone_number, 'N/A') AS merchant_phone,
                u.role AS user_role
            FROM transactions t
            LEFT JOIN users u ON t.merchant_id::text = u.id::text OR t.client_id::text = u.id::text
            WHERE UPPER(t.type) = 'BANK-WITHDRAWAL-COMPLETED'
            ORDER BY t.created_at DESC
            LIMIT 50
        `;

        const result = await pool.query(query);

        res.json({ 
            success: true, 
            history: result.rows 
        });

    } catch (error) {
        console.error("Error al obtener historial ACH:", error);
        res.status(500).json({ success: false, error: "Error al obtener el historial de retiros" });
    }
});

// ==========================================
// ENDPOINT: GET /api/admin/balance (Obtener saldo del Administrador)
// ==========================================
app.get('/api/admin/balance', verifyToken, requireRole('ADMIN'), async (req, res) => {
    // Opcional: Validar que el usuario que hace la petición realmente sea 'admin'
   if (String(req.user?.role || '').toUpperCase() !== 'ADMIN') {
        return res.status(403).json({ success: false, error: 'Acceso denegado. Se requiere rol de administrador.' });
    }

    const adminId = req.user.id; // Obtenido del token verificado

    try {
        // 1. Consultar el balance directamente del usuario admin autenticado
        const adminRes = await pool.query(
            "SELECT id, full_name, balance FROM users WHERE id = $1", 
            [adminId]
        );

        if (adminRes.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Cuenta de administrador no encontrada.' });
        }

        const adminData = adminRes.rows[0];
        const adminBalance = parseFloat(adminData.balance || 0).toFixed(2);

        return res.json({
            success: true,
            balance: adminBalance
        });

    } catch (error) {
        console.error("Error al obtener el balance del admin:", error);
        return res.status(500).json({ success: false, error: 'Error al consultar el balance general.' });
    }
});

// ==========================================
// ENDPOINT: POST /api/agent/withdraw-bank (Exclusivo para Agentes)
// ==========================================
app.post('/api/agent/withdraw-bank', verifyToken, requireRole('AGENT'), async (req, res) => {
    const userId = req.user.id;
    const { amount, bank_name, account_number, account_type } = req.body;

    const withdrawAmount = round2(parseFloat(amount));
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ success: false, error: 'Monto de retiro inválido.' });
    }

    if (!bank_name || !account_number) {
        return res.status(400).json({ success: false, error: 'Proporciona el banco y el número de cuenta de destino.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Bloquear y verificar que el usuario exista
        const userRes = await client.query(
            'SELECT id, balance, role, full_name FROM users WHERE id::text = $1::text FOR UPDATE',
            [String(userId)]
        );

        if (userRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Agente no encontrado.' });
        }

        const userData = userRes.rows[0];
        const currentBalance = round2(parseFloat(userData.balance || 0));

        if (currentBalance < withdrawAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                success: false,
                error: `Saldo insuficiente. Tu saldo disponible como agente es de Q${currentBalance.toFixed(2)}.`
            });
        }

        // Bloquear wallet si existe fila para este usuario
        await client.query(
            'SELECT id FROM wallets WHERE user_id::text = $1::text FOR UPDATE',
            [String(userId)]
        );

        // 2. Descontar el saldo del agente
        await client.query(
            'UPDATE users SET balance = ROUND((balance - $1)::numeric, 2) WHERE id::text = $2::text',
            [withdrawAmount, String(userId)]
        );
        await client.query(
            'UPDATE wallets SET balance = ROUND((balance - $1)::numeric, 2) WHERE user_id::text = $2::text',
            [withdrawAmount, String(userId)]
        );

        // 3. Registrar la transacción pendiente para administración
        const folioUnico = `ACH-AGT-${Date.now().toString().slice(-6)}`;

        await client.query(
            `INSERT INTO transactions (client_id, agent_id, amount, type, bank_name, account_number, account_type, created_at) 
             VALUES ($1, $1, $2, 'AGENT-BANK-WITHDRAWAL-PENDING', $3, $4, $5, NOW())`,
            [String(userId), withdrawAmount, bank_name, account_number, account_type || 'Monetaria']
        );

        await client.query('COMMIT');

        return res.json({
            success: true,
            folio: folioUnico,
            amount: withdrawAmount,
            message: 'Solicitud de retiro bancario enviada con éxito. El administrador procesará tu transferencia.'
        });

    } catch (error) {
        try {
            await client.query('ROLLBACK');
        } catch (rollbackErr) {
            console.error('Error en ROLLBACK (agent withdraw-bank):', rollbackErr);
        }
        console.error('Error en retiro de agente:', error);
        return res.status(500).json({ success: false, error: 'Error interno al procesar el retiro.' });
    } finally {
        client.release();
    }
});

// ==========================================
// Endpoint para que el Comercio o Agente vea el estatus de sus retiros ACH
// ==========================================
app.get('/api/user/withdrawals', verifyToken, async (req, res) => {
    const userId = req.user.id;

    try {
        const query = `
            SELECT id, amount, type, bank_name, account_number, account_type, created_at
            FROM transactions
            WHERE (client_id::text = $1::text OR merchant_id::text = $1::text)
            AND UPPER(type) IN (
                'BANK-WITHDRAWAL-PENDING', 
                'AGENT-BANK-WITHDRAWAL-PENDING', 
                'BANK-WITHDRAWAL-COMPLETED'
            )
            ORDER BY created_at DESC
            LIMIT 20
        `;

        const result = await pool.query(query, [String(userId)]);

        res.json({
            success: true,
            withdrawals: result.rows
        });
    } catch (error) {
        console.error("Error al obtener retiros del usuario:", error);
        res.status(500).json({ success: false, error: "Error interno al obtener los retiros" });
    }
});

// ==========================================
// CANCELAR SOLICITUD DE RETIRO ACH (Comercios y Agentes)
// ==========================================
app.delete('/api/user/withdrawals/:id', verifyToken, async (req, res) => {
  const userId = String(req.user?.id || req.user?.userId || '');
  const withdrawalId = String(req.params.id || '').trim();

  if (!userId || !withdrawalId) {
    return res.status(400).json({ success: false, error: 'Solicitud inválida.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Bloquear fila del usuario primero para mantener orden consistente
    const userRes = await client.query(
      'SELECT id, balance FROM users WHERE id::text = $1::text FOR UPDATE',
      [userId]
    );
    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
    }

    // Bloquear la solicitud pendiente
    const checkQuery = `
      SELECT id, amount, type
      FROM transactions
      WHERE id::text = $1::text
        AND (client_id::text = $2::text OR merchant_id::text = $2::text OR agent_id::text = $2::text)
        AND UPPER(type) IN ('BANK-WITHDRAWAL-PENDING', 'AGENT-BANK-WITHDRAWAL-PENDING')
      FOR UPDATE
    `;
    const checkResult = await client.query(checkQuery, [withdrawalId, userId]);

    if (checkResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        success: false,
        error: 'No se encontró la solicitud pendiente o ya fue procesada.'
      });
    }

    const withdrawalAmount = round2(parseFloat(checkResult.rows[0].amount || 0));

    await client.query('DELETE FROM transactions WHERE id::text = $1::text', [withdrawalId]);

   await client.query(
      'UPDATE users SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2) WHERE id::text = $2::text',
      [withdrawalAmount, userId]
    );

    await client.query(
      'UPDATE wallets SET balance = ROUND((COALESCE(balance, 0) + $1)::numeric, 2), updated_at = NOW() WHERE user_id::text = $2::text',
      [withdrawalAmount, userId]
    );

    await client.query('COMMIT');

    return res.json({
      success: true,
      message: 'Solicitud cancelada y saldo devuelto con éxito.'
    });
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Error en ROLLBACK (delete withdrawal):', rollbackErr);
    }
    console.error("Error al cancelar retiro:", error);
    return res.status(500).json({ success: false, error: 'Error interno al cancelar la solicitud.' });
  } finally {
    client.release();
  }
});

// ==========================================
// 1. REGISTRO CON ENVÍO DE CÓDIGO DE VERIFICACIÓN
// ==========================================
const allowDevCodes = process.env.ALLOW_DEV_CODES === 'true';

app.post('/api/register', async (req, res) => {
  const { phone_number, pin, full_name } = req.body;

  if (!phone_number || !pin) {
    return res.status(400).json({ success: false, error: "Teléfono y PIN son obligatorios" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const pin_hash = await bcrypt.hash(pin, salt);
    const userRole = 'CLIENT';

    // Generar código aleatorio de 6 dígitos
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      `INSERT INTO users (phone_number, pin_hash, full_name, role, balance, is_verified, verification_code) 
       VALUES ($1, $2, $3, $4, $5, FALSE, $6) 
       RETURNING id, phone_number, role`,
      [phone_number, pin_hash, full_name || 'Usuario', userRole, 0.00, verificationCode]
    );

    // 🌟 ZONA DE ENVÍO DE MENSAJE (MODO PRUEBA JSON / LISTO PARA TWILIO)
    /* 
      TODO PARA PRODUCCIÓN (TWILIO):
      const twilio = require('twilio');
      const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
      await client.messages.create({
          body: `Tu código de verificación Tiolito es: ${verificationCode}`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: `+502${phone_number}`
      });
    */

    return res.json({
      success: true,
      requires_verification: true,
      message: 'Cuenta registrada. Ingresa el código de verificación.',
      ...(allowDevCodes ? { dev_code: verificationCode } : {})
    });
  } catch (error) {
    console.error("ERROR EN EL REGISTRO:", error);
    if (error.code === '23505') {
      return res.status(400).json({ success: false, error: "El número ya está registrado" });
    }
    return res.status(500).json({ success: false, error: "Error interno al registrar la cuenta." });
  }
});

// ==========================================
// 2. VERIFICAR EL CÓDIGO DE REGISTRO
// ==========================================
app.post('/api/auth/verify-code', async (req, res) => {
  const { phone_number, code } = req.body;

  try {
    const userRes = await pool.query(
      'SELECT id, role, full_name FROM users WHERE phone_number = $1 AND verification_code = $2',
      [phone_number, code]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Código de verificación incorrecto o inválido.' });
    }

    const user = userRes.rows[0];
    const token = jwt.sign({ id: user.id, role: user.role, name: user.full_name }, JWT_SECRET, { expiresIn: '2h' });

    // Marcar como verificado, limpiar código y establecer sesión activa
    await pool.query(
      'UPDATE users SET is_verified = TRUE, verification_code = NULL, active_token = $1 WHERE id = $2',
      [token, user.id]
    );

    res.json({
      success: true,
      token,
      role: user.role,
      user_id: user.id,
      name: user.full_name,
      message: '¡Cuenta verificada con éxito!'
    });
  } catch (error) {
    console.error("Error al verificar código:", error);
    res.status(500).json({ success: false, error: 'Error interno del servidor.' });
  }
});

// ==========================================
// 3. SOLICITAR RECUPERACIÓN DE CONTRASEÑA
// ==========================================
app.post('/api/auth/forgot-password', async (req, res) => {
    const { phone_number } = req.body;

    try {
        const userResult = await pool.query(`SELECT id FROM users WHERE phone_number = $1`, [phone_number]);
        if (userResult.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'No se encontró una cuenta con este número.' });
        }

        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

        await pool.query(
            `UPDATE users SET reset_code = $1, reset_expires = NOW() + INTERVAL '15 minutes' WHERE phone_number = $2`,
            [resetCode, phone_number]
        );

        /* 
          TODO PARA PRODUCCIÓN (TWILIO):
          await client.messages.create({
              body: `Tu código para recuperar contraseña en Tiolito es: ${resetCode}`,
              from: process.env.TWILIO_PHONE_NUMBER,
              to: `+502${phone_number}`
          });
        */

        return res.json({
            success: true,
            message: 'Código de recuperación generado.',
            ...(process.env.ALLOW_DEV_CODES === 'true' ? { dev_code: resetCode } : {})
        });
    } catch (error) {
        console.error('Error en forgot-password:', error);
        return res.status(500).json({ success: false, error: 'Error interno del servidor.' });
    }
});

// ==========================================
// 4. RESTABLECER CONTRASEÑA CON CÓDIGO
// ==========================================
app.post('/api/auth/reset-password', async (req, res) => {
    const { phone_number, code, new_password } = req.body;

    if (!phone_number || !code || !new_password) {
        return res.status(400).json({ success: false, error: 'Todos los campos son obligatorios.' });
    }

    try {
        const checkResult = await pool.query(
            `SELECT id FROM users WHERE phone_number = $1 AND reset_code = $2 AND reset_expires > NOW()`,
            [phone_number, code]
        );

        if (checkResult.rowCount === 0) {
            return res.status(400).json({ success: false, error: 'El código es inválido o ha expirado.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(new_password, salt);

        await pool.query(
            `UPDATE users SET pin_hash = $1, reset_code = NULL, reset_expires = NULL WHERE phone_number = $2`,
            [hashedPassword, phone_number]
        );

        res.json({ success: true, message: 'Contraseña actualizada con éxito.' });
    } catch (error) {
        console.error('Error en reset-password:', error);
        res.status(500).json({ success: false, error: 'Error al actualizar la contraseña.' });
    }
});

// ==========================================
// ENDPOINT: GET /api/agent/commissions-summary (Ajustado a hora de Guatemala)
// ==========================================
app.get('/api/agent/commissions-summary', verifyToken, requireRole('AGENT'), async (req, res) => {
    const agentId = req.user.id;

    try {
        // Comparamos usando la fecha de Guatemala (America/Guatemala)
        const query = `
            SELECT amount
            FROM transactions
            WHERE agent_id::text = $1::text
              AND UPPER(type) = 'CASH-OUT'
              AND (created_at AT TIME ZONE 'America/Guatemala')::date = 
                  (NOW() AT TIME ZONE 'America/Guatemala')::date
        `;

        const result = await pool.query(query, [String(agentId)]);
        const retiros = result.rows;

        let comisionTotalAgenteHoy = 0;

        retiros.forEach(tx => {
            const monto = parseFloat(tx.amount);
            let comisionTotalTransaccion = 0;

            if (monto <= 200.00) {
                comisionTotalTransaccion = 2.00;
            } else if (monto <= 500.00) {
                comisionTotalTransaccion = 4.00;
            } else if (monto <= 1000.00) {
                comisionTotalTransaccion = 8.00;
            } else if (monto <= 2000.00) {
                comisionTotalTransaccion = 16.00;
            }

            const comisionAgenteTx = comisionTotalTransaccion * 0.70;
            comisionTotalAgenteHoy += comisionAgenteTx;
        });

        res.json({
            success: true,
            total_retiros: retiros.length,
            comision_estimada_hoy: comisionTotalAgenteHoy.toFixed(2)
        });

    } catch (error) {
        console.error("Error al calcular comisiones del agente:", error);
        res.status(500).json({ success: false, error: "Error al calcular comisiones" });
    }
});

// ==========================================
// ENDPOINT: GET /api/admin/financial-overview (Horario Guatemala + Auditoría Mensual)
// ==========================================
app.get('/api/admin/financial-overview', verifyToken, requireRole('ADMIN'), async (req, res) => {
  try {
    const balancesRes = await pool.query(`
      SELECT
        UPPER(COALESCE(role, '')) AS role,
        COALESCE(SUM(balance), 0) AS total_balance,
        COUNT(*) AS users_count
      FROM users
      WHERE UPPER(COALESCE(role, '')) IN ('CLIENT', 'MERCHANT', 'COMERCIO', 'AGENT')
      GROUP BY UPPER(COALESCE(role, ''))
    `);

    const commissionsRes = await pool.query(`
      SELECT
        COALESCE(SUM(admin_commission), 0) AS total_admin_commissions,
        COALESCE(SUM(CASE
          WHEN (created_at AT TIME ZONE 'America/Guatemala')::date =
               (NOW() AT TIME ZONE 'America/Guatemala')::date
          THEN admin_commission ELSE 0
        END), 0) AS today_admin_commissions,
        COALESCE(SUM(CASE
          WHEN DATE_TRUNC('month', created_at AT TIME ZONE 'America/Guatemala') =
               DATE_TRUNC('month', NOW() AT TIME ZONE 'America/Guatemala')
          THEN admin_commission ELSE 0
        END), 0) AS month_admin_commissions
      FROM platform_commissions
    `);

    const volumeTodayRes = await pool.query(`
      SELECT
        UPPER(COALESCE(type, '')) AS type,
        COUNT(*) AS tx_count,
        COALESCE(SUM(amount), 0) AS total_amount
      FROM transactions
      WHERE (created_at AT TIME ZONE 'America/Guatemala')::date =
            (NOW() AT TIME ZONE 'America/Guatemala')::date
      GROUP BY UPPER(COALESCE(type, ''))
      ORDER BY total_amount DESC
    `);

    const volumeMonthRes = await pool.query(`
      SELECT
        UPPER(COALESCE(type, '')) AS type,
        COUNT(*) AS tx_count,
        COALESCE(SUM(amount), 0) AS total_amount
      FROM transactions
      WHERE DATE_TRUNC('month', created_at AT TIME ZONE 'America/Guatemala') =
            DATE_TRUNC('month', NOW() AT TIME ZONE 'America/Guatemala')
      GROUP BY UPPER(COALESCE(type, ''))
      ORDER BY total_amount DESC
    `);

    const byRole = { client: 0, merchant: 0, agent: 0 };
    for (const row of balancesRes.rows) {
      const val = round2(parseFloat(row.total_balance || 0));
      if (row.role === 'CLIENT') byRole.client = round2(byRole.client + val);
      else if (row.role === 'MERCHANT' || row.role === 'COMERCIO') byRole.merchant = round2(byRole.merchant + val);
      else if (row.role === 'AGENT') byRole.agent = round2(byRole.agent + val);
    }

    const totalThirdPartyBalances = round2(byRole.client + byRole.merchant + byRole.agent);
    const commRow = commissionsRes.rows[0] || {};

    const monthNamesEs = [
      'Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio',
      'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'
    ];
    const gtNowParts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Guatemala',
      year: 'numeric',
      month: '2-digit'
    }).formatToParts(new Date());
    const gtYear = gtNowParts.find((p) => p.type === 'year')?.value || String(new Date().getFullYear());
    const gtMonthIdx = Math.max(
      0,
      Math.min(11, parseInt(gtNowParts.find((p) => p.type === 'month')?.value || '1', 10) - 1)
    );
    const auditMonthLabel = `${monthNamesEs[gtMonthIdx]} ${gtYear}`;

    const formattedMonthVolume = volumeMonthRes.rows.map((r) => ({
      type: r.type,
      tx_count: parseInt(r.tx_count || 0, 10),
      total_amount: round2(parseFloat(r.total_amount || 0)).toFixed(2)
    }));

    const totalVolumeMonth = round2(
      formattedMonthVolume.reduce((acc, item) => acc + parseFloat(item.total_amount || 0), 0)
    );

    return res.json({
      success: true,
      audit_period: {
        month_name: monthNamesEs[gtMonthIdx],
        year: Number(gtYear),
        label: auditMonthLabel,
        timezone: 'America/Guatemala'
      },
      balances_by_role: byRole,
      total_third_party_balances: totalThirdPartyBalances,
      commissions: {
        today_admin: round2(parseFloat(commRow.today_admin_commissions || 0)).toFixed(2),
        month_admin: round2(parseFloat(commRow.month_admin_commissions || 0)).toFixed(2),
        total_admin: round2(parseFloat(commRow.total_admin_commissions || 0)).toFixed(2)
      },
      volume_today: volumeTodayRes.rows.map((r) => ({
        type: r.type,
        tx_count: parseInt(r.tx_count || 0, 10),
        total_amount: round2(parseFloat(r.total_amount || 0)).toFixed(2)
      })),
      volume_month: formattedMonthVolume,
      total_volume_month: totalVolumeMonth.toFixed(2)
    });
  } catch (error) {
    console.error('Error en GET /api/admin/financial-overview:', error);
    return res.status(500).json({ success: false, error: 'Error al obtener el resumen financiero.' });
  }
});
 
// Iniciar servidor
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});    