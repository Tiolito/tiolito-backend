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

  socket.on('disconnect', () => {
    console.log('Socket desconectado:', socket.id);
  });
});
const JWT_SECRET = 'secreto_jwt';
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
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
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader) {
        return res.status(401).json({ success: false, error: "Acceso denegado. Token no proporcionado." });
    }

    const token = authHeader.split(' ')[1]; // El formato es "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, error: "Token malformado." });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ success: false, error: "Token inválido o expirado." });
        }
        
        req.user = decoded; // Guardamos los datos del usuario decodificados en la petición
        next();
    });
};

// ==========================================
// 3. ENDPOINT: GET /api/wallets/:user_id
// ========================================== 
app.get('/api/wallets/:user_id', async (req, res) => {
    const { user_id } = req.params;

    try {
        const result = await pool.query(
            'SELECT w.id, w.user_id, w.balance, w.currency, w.updated_at, u.full_name, u.role FROM wallets w JOIN users u ON w.user_id = u.id WHERE w.user_id = $1',
            [user_id]
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
        res.status(500).json({ success: false, error: error.message });
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
      'SELECT id, full_name, role, pin_hash FROM users WHERE phone_number = $1',
      [phone_number]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Usuario no encontrado" });
    }

    const user = userResult.rows[0];
    
    // 🔒 Validación estricta únicamente mediante bcrypt
    const isValidPassword = await bcrypt.compare(inputPassword, user.pin_hash);

    if (!isValidPassword) {
      return res.status(401).json({ success: false, error: "Contraseña incorrecta" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.full_name },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({ success: true, token, role: user.role, user_id: user.id, name: user.full_name });

  } catch (error) {
    console.error("ERROR EN EL LOGIN:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/register', async (req, res) => {
  const { phone_number, pin, full_name, role } = req.body;

  if (!phone_number || !pin) {
    return res.status(400).json({ success: false, error: "Teléfono y PIN son obligatorios" });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const pin_hash = await bcrypt.hash(pin, salt); 
    const userRole = 'CLIENT';

    const result = await pool.query(
      `INSERT INTO users (phone_number, pin_hash, full_name, role, balance) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, phone_number, role`,
      [phone_number, pin_hash, full_name || 'Usuario', userRole, 0.00]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, role: user.role }, 'secreto_jwt');

    return res.json({
      success: true,
      token,
      role: user.role,
      message: 'Usuario registrado exitosamente'
    });
  } catch (error) {
    console.error("ERROR EN EL REGISTRO:", error);
    if (error.code === '23505') {
      return res.status(400).json({ success: false, error: "El número ya está registrado" });
    }
    return res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// 4. ENDPOINT: GET /api/transactions/:user_id
// ==========================================
app.get('/api/transactions/:user_id', async (req, res) => {
    const { user_id } = req.params;

    try {
        const result = await pool.query(
            'SELECT * FROM transactions WHERE client_id = $1 ORDER BY created_at DESC',
            [user_id]
        );

        res.status(200).json({
            success: true,
            count: result.rows.length,
            transactions: result.rows
        });

    } catch (error) {
        console.error("Error en GET /api/transactions:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// 5. ENDPOINT: POST /api/transfer (Transferencia P2P por Teléfono)
// ==========================================
app.post('/api/transfer', verifyToken, validarLimitesAML, async (req, res) => {
    const sender_id = req.user.id; // Obtenemos el ID del emisor desde el Token JWT
    const { receiver_phone, amount } = req.body;

    if (!receiver_phone || !amount || parseFloat(amount) <= 0) {
        return res.status(400).json({ success: false, error: "Ingresa un número de teléfono y un monto válido." });
    }

    const cleanReceiverPhone = String(receiver_phone).trim();
    const transferAmount = parseFloat(amount);
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

        // 2. Validar si intenta transferirse a su propio número
        if (sender.phone_number && sender.phone_number.trim() === cleanReceiverPhone) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "No puedes transferir fondos a la misma billetera" });
        }

        // 3. Buscar al receptor por su número de teléfono
        const receiverResult = await client.query('SELECT id, phone_number, balance FROM users WHERE phone_number = $1 FOR UPDATE', [cleanReceiverPhone]);
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

        // 4. Validar saldo suficiente en la tabla users (o wallets según tu diseño)
        const senderBalance = parseFloat(sender.balance || 0);
        if (senderBalance < transferAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Saldo insuficiente para realizar la transferencia" });
        }

        // 5. Descontar al emisor
        await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id = $2',
            [transferAmount, sender_id]
        );

        // 6. Acreditar al receptor
        await client.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2',
            [transferAmount, receiver.id]
        );

        // 7. Registrar la transacción
        const transactionResult = await client.query(
            `INSERT INTO transactions (agent_id, client_id, amount, type, created_at)
             VALUES ($1, $2, $3, 'TRANSFER-OUT', NOW()) RETURNING *;`,
            [sender_id, receiver.id, transferAmount]
        );

        await client.query('COMMIT');

        // Consultar nombres de emisor y receptor para el comprobante
        const userNamesRes = await client.query(
            'SELECT id, full_name, phone_number FROM users WHERE id = $1 OR id = $2',
            [sender_id, receiver.id]
        );

        const senderInfo = userNamesRes.rows.find(u => u.id === sender_id) || { full_name: req.user.name || 'Emisor', phone_number: sender.phone_number };
        const receiverInfo = userNamesRes.rows.find(u => u.id === receiver.id) || { full_name: 'Destinatario', phone_number: cleanReceiverPhone };

       // 👈 Usamos directamente el ID de la base de datos para mantener el formato corto TRX-ID
        const shortFolio = `TRX-${transactionResult.rows[0].id}`;

        // 🚀 NUEVO: Preparamos el paquete de datos para el socket en tiempo real
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

        // 🚀 NUEVO: Notificar instantáneamente al receptor en su propia sala
        io.to(`client_${receiver.id}`).emit('transfer_received', transferPayload);

        res.status(200).json({
            success: true,
            transaction: transferPayload
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error en /api/transfer:", error);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        client.release();
    }
});

// ==========================================
// 6. ENDPOINT: POST /api/merchant/charge (Cobro a Negocios / Comercios)
// ==========================================
app.post('/api/merchant/charge', verifyToken, async (req, res) => {
    const { client_id, merchant_id, amount } = req.body;
    const userIdFromToken = req.user.id; // Del token JWT
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

       // Validar que el comercio exista, pertenezca al usuario y traer sus límites
const merchantResult = await client.query(
  'SELECT tier, max_per_tx, max_daily FROM merchants WHERE id = $1 AND owner_user_id = $2',
  [merchant_id, userIdFromToken]
);

if (merchantResult.rows.length === 0) {
  await client.query('ROLLBACK');
  return res.status(403).json({
    success: false,
    error: "No tienes autorización o el comercio no existe"
  });
}

const merchant = merchantResult.rows[0];
const maxPerTx = Number(merchant.max_per_tx);
const maxDaily = Number(merchant.max_daily);
const payAmount = Number(amount);

// 2. Validar límite por transacción individual
if (payAmount > maxPerTx) {
  await client.query('ROLLBACK');
  return res.status(400).json({
    success: false,
    error: `Este comercio tiene un límite máximo de Q${maxPerTx.toFixed(2)} por transacción.`
  });
}

// 3. Validar acumulado diario de ventas del comercio (usando client.query)
const dailySalesResult = await client.query(
  `SELECT COALESCE(SUM(amount), 0) AS total_today 
   FROM transactions 
   WHERE merchant_id = $1 
     AND created_at::date = CURRENT_DATE`,
  [merchant_id]
);

const totalToday = Number(dailySalesResult.rows[0].total_today);

if (totalToday + payAmount > maxDaily) {
  await client.query('ROLLBACK');
  return res.status(400).json({
    success: false,
    error: `El comercio ha alcanzado su límite diario de ventas (Máx. Q${maxDaily.toFixed(2)}).`
  });
}

        if (merchantResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(403).json({ 
                success: false, 
                error: "No tienes autorización para realizar cobros a nombre de este comercio" 
            });
        }

        const merchantName = merchantResult.rows[0].name;
        const merchantUserId = merchantResult.rows[0].owner_user_id; //

        if (client_id === merchantUserId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Un comercio no se puede cobrar a sí mismo" });
        }

        const chargeAmount = parseFloat(amount);
        if (isNaN(chargeAmount) || chargeAmount <= 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "El monto del cobro debe ser mayor a cero" });
        }

        // Verificar y bloquear la billetera del cliente pagador
        const clientWallet = await client.query(
            'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
            [client_id]
        );

        if (clientWallet.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Billetera del cliente no encontrada" });
        }

        const clientBalance = parseFloat(clientWallet.rows[0].balance);
        if (clientBalance < chargeAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Saldo insuficiente en la billetera del cliente" });
        }

        // Verificar y bloquear la billetera del comercio receptor
        const merchantWallet = await client.query(
            'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
            [merchantUserId]
        );

        if (merchantWallet.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Billetera del comercio receptor no encontrada" });
        }

        // Descontar saldo al cliente
        await client.query(
            'UPDATE wallets SET balance = balance - $1, updated_at = NOW() WHERE user_id = $2',
            [chargeAmount, client_id]
        );

        // Acreditar saldo al comercio
        await client.query(
            'UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2',
            [chargeAmount, merchantUserId]
        );

        // Registrar la transacción de cobro incluyendo el merchant_id y agent_id del usuario
const transactionResult = await client.query(
    `INSERT INTO transactions (agent_id, client_id, merchant_id, amount, type, created_at)
     VALUES ($1, $2, $3, $4, 'MERCHANT-PAYMENT', NOW()) RETURNING *;`,
    [merchantUserId, client_id, merchant_id, chargeAmount]
);

        await client.query('COMMIT');
        res.status(200).json({
            success: true,
           message: `Pago procesado con éxito para ${merchantName}`,
            transaction: transactionResult.rows[0]
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error en /api/merchant/charge:", error);
        res.status(500).json({ success: false, error: error.message });
    } finally {
        client.release();
    }
});

// ==========================================
// 8. ENDPOINT: POST /api/merchant/refund (Reversión de cobros)
// ==========================================
app.post('/api/merchant/refund', verifyToken, async (req, res) => {
    const { transaction_id } = req.body;
    const merchantId = req.user.id;
    
    if (!transaction_id) {
        return res.status(400).json({ success: false, error: "ID de transacción no proporcionado" });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const cleanId = String(transaction_id).replace('TRX-', '').trim();

        // 1. Buscar la transacción original
        const txResult = await client.query(
            `SELECT * FROM transactions 
             WHERE id::text = $1 
               AND (agent_id::text = $2::text OR merchant_id::text = $2::text)`,
            [cleanId, String(merchantId)]
        );

        if (txResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Transacción no encontrada o no autorizada" });
        }

        const transaction = txResult.rows[0];
        const refundAmount = parseFloat(transaction.amount);
        const clientId = transaction.client_id;

        // 2. Devolver el dinero al cliente (si existe)
        if (clientId) {
            await client.query(
                'UPDATE users SET balance = balance + $1 WHERE id::text = $2::text',
                [refundAmount, String(clientId)]
            );
        }

        // 3. Descontar el dinero del saldo/caja del comercio
        await client.query(
            'UPDATE users SET balance = balance - $1 WHERE id::text = $2::text',
            [refundAmount, String(merchantId)]
        );

        // 4. Eliminar el registro original de la venta
        await client.query('DELETE FROM transactions WHERE id::text = $1::text', [cleanId]);

        // 5. Registrar la transacción de reembolso reutilizando agent_id y merchant_id originales
        const refundTx = await client.query(
            `INSERT INTO transactions (agent_id, client_id, merchant_id, amount, type, created_at)
             VALUES ($1, $2, $3, $4, 'REFUND', NOW()) RETURNING id, created_at`,
            [transaction.agent_id, clientId, transaction.merchant_id, refundAmount]
        );

        io.to(`client_${clientId}`).emit('transaction_update', {
    type: 'REFUND',
    message: `Has recibido una devolución de Q${refundAmount}`,
    amount: refundAmount
});

        await client.query('COMMIT');
        
        res.json({ 
            success: true, 
            message: `Reembolso de Q${refundAmount} procesado con éxito`,
            refund_transaction_id: refundTx.rows[0].id
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error al procesar la devolución:", error);
        res.status(500).json({ success: false, error: "Error al procesar el reembolso en el servidor: " + error.message });
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

// ==========================================
// 10. ENDPOINT: POST /api/client/deposit (Recargar saldo)
// ==========================================
app.post('/api/client/deposit', verifyToken, async (req, res) => {
    const userIdFromToken = req.user.id;
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ success: false, error: "El monto debe ser mayor a cero" });
    }

    try {
        const result = await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING id, full_name, balance',
            [amount, userIdFromToken]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        res.json({ 
            success: true, 
            message: "Depósito realizado con éxito", 
            client: result.rows[0] 
        });
    } catch (error) {
        console.error("Error al procesar el depósito:", error);
        res.status(500).json({ success: false, error: "Error al realizar la recarga" });
    }
});

// ==========================================
// 11. ENDPOINT: GET /api/client/transactions (Historial completo del cliente)
// ==========================================
app.get('/api/client/transactions', verifyToken, async (req, res) => {
    const userIdFromToken = req.user.id;

    try {
        const query = `
            SELECT 
                t.id, 
                t.amount, 
                t.type AS original_type,
                CASE 
                    WHEN UPPER(t.type) = 'MERCHANT-PAYMENT' THEN 'Pago a Comercio'
                    WHEN UPPER(t.type) IN ('CASH-IN', 'CASH_IN') THEN 'Depósito (Cash-In)'
                    WHEN UPPER(t.type) IN ('CASH-OUT', 'CASH_OUT') THEN 'Retiro (Cash-Out)'
                    WHEN UPPER(t.type) = 'REFUND' THEN 'Reembolso Recibido'
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
                client_user.phone_number AS client_phone -- 👈 Asegurar esta línea
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
// 12. ENDPOINT: POST /api/agent/deposit (Recarga a cliente por punto físico)
// ==========================================
app.post('/api/agent/deposit', verifyToken, async (req, res) => {
    const agentUserId = req.user.id;
    const { client_id, amount } = req.body;

    // Verificar datos de entrada
    if (!client_id || !amount || amount <= 0) {
        return res.status(400).json({ success: false, error: "Cliente y monto válido (mayor a 0) son requeridos" });
    }

    try {
        // Aumentar el saldo del cliente
        const updateClient = await pool.query(
            'UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING id, full_name, balance',
            [amount, client_id]
        );

        if (updateClient.rows.length === 0) {
            return res.status(404).json({ success: false, error: "Cliente no encontrado" });
        }

        res.json({
            success: true,
            message: "Recarga realizada exitosamente al cliente",
            agent_id: agentUserId,
            client: updateClient.rows[0]
        });
    } catch (error) {
        console.error("Error al procesar la recarga del agente:", error);
        res.status(500).json({ success: false, error: "Error interno al procesar la recarga" });
    }
});

// ENDPOINT: GET /api/agent/transactions (Historial de transacciones del agente)
// ==========================================
app.get('/api/agent/transactions', verifyToken, async (req, res) => {
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
        -- 👈 Aquí está la corrección: Busca el nombre en la tabla users y si no, usa el nombre del token (req.user.name) o 'Agente Autorizado'
        COALESCE(agent_user.full_name, $2, 'Agente Autorizado') AS agent_name
      FROM transactions t 
      LEFT JOIN users u ON t.client_id::text = u.id::text 
      LEFT JOIN users agent_user ON t.agent_id::text = agent_user.id::text
      WHERE t.agent_id::text = $1::text
    `;
    
    // Pasamos el ID del agente y el nombre del usuario logueado desde el token como parámetros
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

app.post('/api/cash-in', verifyToken, validarLimitesAML, async (req, res) => {
  try {
    const targetPhone = req.body.phone_number || req.body.client_phone || req.body.phone;
    const amount = req.body.amount || req.body.monto;

    let agent_id = null;
    const authHeader = req.headers['authorization'];
  
    if (authHeader) {
      try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto_jwt');
        agent_id = decoded.id || decoded.userId;
      } catch (e) {
        console.log("Error al verificar token en cash-in:", e.message);
      }
    }

    if (!agent_id) {
      return res.status(401).json({ success: false, error: "No autorizado. Inicia sesión como agente." });
    }

    if (!targetPhone || !amount) {
      return res.status(400).json({ success: false, error: "Falta el teléfono o el monto" });
    }

    const depositAmount = parseFloat(amount);

    // 🛑 Validar saldo del agente antes de depositar
    const agentCheck = await pool.query('SELECT balance FROM users WHERE id = $1', [agent_id]);
    if (agentCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Agente no encontrado" });
    }

    const agentBalance = parseFloat(agentCheck.rows[0].balance || 0);
    if (agentBalance < depositAmount) {
      return res.status(400).json({ 
        success: false, 
        error: `Saldo de agente insuficiente. Tu saldo disponible es de Q${agentBalance.toFixed(2)} y necesitas Q${depositAmount.toFixed(2)}.` 
      });
    }

    let clientResult = await pool.query(
      'SELECT id, full_name, balance FROM users WHERE phone_number = $1',
      [targetPhone]
    );

    let client_id;
    let newBalance;
    let clientName = 'Cliente Validado';

    if (clientResult.rows.length === 0) {
      const newUser = await pool.query(
        'INSERT INTO users (phone_number, balance, full_name) VALUES ($1, $2, $3) RETURNING id, balance, full_name',
        [targetPhone, amount, 'Cliente Nuevo']
      );
      client_id = newUser.rows[0].id;
      newBalance = parseFloat(amount);
      clientName = newUser.rows[0].full_name;
    } else {
      const client = clientResult.rows[0];
      client_id = client.id;
      clientName = client.full_name || 'Cliente';
      newBalance = parseFloat(client.balance || 0) + parseFloat(amount);

      await pool.query('UPDATE users SET balance = $1 WHERE id = $2', [newBalance, client_id]);
      await pool.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [amount, agent_id]);
      await pool.query('UPDATE wallets SET balance = balance - $1 WHERE user_id = $2', [amount, agent_id]);
    }

    // 🔍 CONSULTAR EL NOMBRE REAL DEL AGENTE DIRECTAMENTE DE LA BASE DE DATOS
    const agentInfoRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [agent_id]);
    const realAgentName = agentInfoRes.rows[0]?.full_name || 'Punto Agente Tiolito';

    // 1. Generamos el folio único de autorización
    const folioUnico = `TRX-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

   // 2. Registrar transacción (Agregando RETURNING id)
    const txResult = await pool.query(
        "INSERT INTO transactions (agent_id, client_id, amount, type) VALUES ($1, $2, $3, 'CASH-IN') RETURNING id, created_at",
        [agent_id, client_id, amount]
    );
    const transactionIdShort = txResult.rows[0].id;

    // 🚀 Avisar al cliente en tiempo real
    io.to(`client_${client_id}`).emit('balance_updated', {
        type: "Depósito (Cash-In)",
        amount: amount,
        created_at: new Date()
    });

    // 3. Devolvemos la respuesta con el nombre real del agente
    return res.json({
        success: true,
        new_balance: newBalance,
        transaction: {
            id: transactionIdShort,
            folio: folioUnico,
            type: "Depósito (Cash-In)",
            agent_name: realAgentName,     // 👈 Nombre real garantizado desde la BD
            client_name: clientName,   
            client_phone: targetPhone, 
            amount: amount,
            created_at: new Date()
        }
    });
  } catch (error) {
    console.error("ERROR EN CASH-IN:", error);
    return res.status(500).json({ success: false, error: error.message });
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

app.post('/api/cash-out', verifyToken, validarLimitesAML, async (req, res) => {
  try {
    const targetPhone = req.body.client_phone || req.body.phone || req.body.phoneNumber || req.body.phone_number;
    const amount = req.body.amount || req.body.monto;

    let agent_id = null;
    let agentName = 'Punto Agente Tiolito'; // 👈 Definimos el valor por defecto aquí
    const authHeader = req.headers['authorization'];
  
    if (authHeader) {
      try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto_jwt');
        agent_id = decoded.id || decoded.userId;
        
        // 👈 ¡Atrapamos el nombre directamente del token al instante!
        if (decoded.name) {
          agentName = decoded.name;
        }
      } catch (e) {
        console.log("Error al verificar token en cash-in:", e.message);
      }
    }

    if (!agent_id) {
      return res.status(401).json({ success: false, error: "No autorizado. Inicia sesión como agente." });
    }

    if (!targetPhone || !amount) {
      return res.status(400).json({ success: false, error: "Falta el teléfono o el monto" });
    }

    const withdrawAmount = parseFloat(amount);

    // 🚀 Calcular comisiones usando la función integrada
    const comisiones = calcularYDividirComision(withdrawAmount);
    const totalDescuentoCliente = withdrawAmount + comisiones.comisionTotal;

    // Buscar al cliente por número de teléfono
    const clientResult = await pool.query(
      'SELECT id, balance FROM users WHERE phone_number = $1',
      [targetPhone]
    );

    if (clientResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Cliente no encontrado" });
    }

    const client = clientResult.rows[0];
    const client_id = client.id;
    const currentBalance = parseFloat(client.balance || 0);

    // Validar que el cliente tenga suficiente saldo para el retiro + la comisión total
    if (currentBalance < totalDescuentoCliente) {
      return res.status(400).json({ 
        success: false, 
        error: `Saldo insuficiente. Necesitas Q${totalDescuentoCliente.toFixed(2)} (incluye Q${comisiones.comisionTotal.toFixed(2)} de comisión)` 
      });
    }

    const newBalance = currentBalance - totalDescuentoCliente;

    // 1. Actualizar el saldo del cliente (restando retiro + comisión total)
    await pool.query(
      'UPDATE users SET balance = $1 WHERE id = $2',
      [newBalance, client_id]
    );

    // 2. Actualizar el saldo del agente (le sumamos el retiro + su 70% de comisión)
    const totalAbonoAgente = withdrawAmount + comisiones.comisionAgente;
    await pool.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2', 
      [totalAbonoAgente, agent_id]
    );

    await pool.query(
      'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2',
      [totalAbonoAgente, agent_id]
    );

    // ==========================================================
    // 🚀 3. ABONAR AUTOMÁTICAMENTE EL 30% DE LA COMISIÓN A TIOLITO
    // ==========================================================
    try {
      const adminResult = await pool.query(
        "SELECT id FROM users WHERE role = 'admin' OR phone_number = '00000000' LIMIT 1"
      );

      if (adminResult.rows.length > 0) {
        const admin_id = adminResult.rows[0].id;

        // Sumar el 30% a la cuenta users del admin
        await pool.query(
          'UPDATE users SET balance = balance + $1 WHERE id = $2',
          [comisiones.comisionTiolito, admin_id]
        );

        // Sumar el 30% a la billetera (wallet) del admin si existe
        try {
          await pool.query(
            'UPDATE wallets SET balance = balance + $1 WHERE user_id = $2',
            [comisiones.comisionTiolito, admin_id]
          );
        } catch (errWallet) {
          // Ignora si la wallet del admin no aplica
        }
      }
    } catch (adminErr) {
      console.error("Error abonando comisión a administración:", adminErr.message);
    }

    // 4. Generar folio único para el comprobante de Retiro
    const folioUnico = `TRX-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

    // Registrar la transacción de retiro (Guardamos el monto y la comisión generada)
    const txResult = await pool.query(
      "INSERT INTO transactions (agent_id, client_id, amount, type) VALUES ($1, $2, $3, 'CASH-OUT') RETURNING id, created_at",
      [agent_id, client_id, withdrawAmount]
    );
    const transactionIdShort = txResult.rows[0].id;

    const code = req.body.code;
    if (code) {
      await pool.query(
        "UPDATE withdrawal_codes SET status = 'USED' WHERE code = $1",
        [code]
      );
    }

    // 🚀 Avisar al cliente en tiempo real sobre el retiro
    io.to(`client_${client_id}`).emit('balance_updated', {
        type: "Retiro (Cash-Out)",
        amount: withdrawAmount,
        commission: comisiones.comisionTotal,
        created_at: new Date()
    });

    // Consultar el nombre real del agente directamente de la base de datos
    const agentInfoRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [agent_id]);
    const realAgentName = agentInfoRes.rows[0]?.full_name || agentName || 'Punto Agente Tiolito';

    const clientInfoRes = await pool.query('SELECT full_name FROM users WHERE id::text = $1::text', [String(client_id)]);
    const clientName = clientInfoRes.rows[0]?.full_name || 'Cliente';
    const clientPhone = targetPhone;

    // 5. Retornar la respuesta con el detalle financiero completo
    return res.json({
            success: true,
            new_balance: newBalance,
            detalles_comision: comisiones,
            transaction: {
                id: transactionIdShort,
                folio: folioUnico,
                type: "Retiro (Cash-Out)",
                agent_name: realAgentName,   
                client_name: clientName,     
                client_phone: clientPhone,   
                amount: withdrawAmount,
                commission: comisiones.comisionTotal,
                created_at: new Date()
            }
    });
  } catch (error) {
    console.error("ERROR EN CASH-OUT:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Ruta para validar un código o QR de retiro
app.post('/api/cash-out/validate-code', async (req, res) => {
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
app.get('/api/transactions/history', async (req, res) => {
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

app.post('/api/agent/register-client', async (req, res) => {
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
    return res.status(500).json({ success: false, error: error.message });
  }
});

// Obtener el saldo del agente
app.get('/api/agent/balance', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) {
            
            return res.status(401).json({ error: 'No token' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto_jwt');
        
        
        const agent_id = decoded.id; 
       

        const result = await pool.query('SELECT balance FROM users WHERE id = $1', [agent_id]);
        
        
        if (result.rows.length > 0) {
            return res.json({ balance: result.rows[0].balance });
        } else {
            
            return res.status(404).json({ error: 'Billetera no encontrada' });
        }
    } catch (error) {
        console.error("ERROR DETALLADO EN /api/agent/balance:", error.message);
        return res.status(500).json({ error: error.message });
    }
});

// Buscar cliente por teléfono
app.get('/api/users/lookup/:phone', async (req, res) => {
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
    return res.status(500).json({ success: false, error: error.message });
  }
});


// Ruta para consultar el nombre del cliente por teléfono
app.post('/api/consult-client', async (req, res) => {
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
app.post('/api/cierre-caja', async (req, res) => {
  try {
    const { efectivo_fisico, fondo_inicial = 0 } = req.body;

    // Capturar agente desde el token
    let agent_id = 1;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, 'secreto_jwt');
        agent_id = decoded.id || decoded.userId || 1;
      } catch (e) {
        console.log("Error decodificando token en cierre de caja:", e.message);
      }
    }

    if (efectivo_fisico === undefined || efectivo_fisico === null) {
      return res.status(400).json({ error: 'Ingresa la cantidad de efectivo físico.' });
    }

    // 1. Obtener la fecha del último corte registrado de este agente
    const ultimoCorteResult = await pool.query(
      'SELECT created_at FROM caja_cortes WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1',
      [agent_id]
    );

    const fechaUltimoCorte = ultimoCorteResult.rows.length > 0 
      ? ultimoCorteResult.rows[0].created_at 
      : '1970-01-01 00:00:00'; // Si nunca ha hecho corte, toma desde el inicio

    // 2. Calcular Total Cash-In desde el último corte
    const cashInQuery = `
      SELECT COALESCE(SUM(amount), 0) AS total_cash_in
      FROM transactions
      WHERE agent_id = $1
        AND LOWER(type) IN ('cash_in', 'cash-in', 'deposit', 'deposito', 'ingreso')
        AND created_at > $2
    `;
    const cashInResult = await pool.query(cashInQuery, [agent_id, fechaUltimoCorte]);
    const totalCashIn = parseFloat(cashInResult.rows[0].total_cash_in);

    // 3. Calcular Total Cash-Out desde el último corte
    const cashOutQuery = `
      SELECT COALESCE(SUM(amount), 0) AS total_cash_out
      FROM transactions
      WHERE agent_id = $1
        AND LOWER(type) IN ('cash_out', 'cash-out', 'withdrawal', 'retiro')
        AND created_at > $2
    `;
    const cashOutResult = await pool.query(cashOutQuery, [agent_id, fechaUltimoCorte]);
    const totalCashOut = parseFloat(cashOutResult.rows[0].total_cash_out);

    // 4. Cálculos matemáticos del corte
    const fondoInicialNum = parseFloat(fondo_inicial) || 0;
    const efectivoEsperado = fondoInicialNum + totalCashIn - totalCashOut;
    const efectivoFisicoNum = parseFloat(efectivo_fisico);
    const diferencia = efectivoFisicoNum - efectivoEsperado;

    let estado = 'Cuadrado';
    if (diferencia > 0) estado = `Sobrante (+Q${diferencia.toFixed(2)})`;
    if (diferencia < 0) estado = `Faltante (-Q${Math.abs(diferencia).toFixed(2)})`;

    // 5. Guardar este corte de caja en la base de datos
    await pool.query(
      `INSERT INTO caja_cortes 
       (agent_id, fondo_inicial, total_cash_in, total_cash_out, efectivo_esperado, efectivo_fisico, diferencia, estado)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [agent_id, fondoInicialNum, totalCashIn, totalCashOut, efectivoEsperado, efectivoFisicoNum, diferencia, estado]
    );

    // 6. Retornar respuesta al cliente
    res.json({
      fondo_inicial: fondoInicialNum.toFixed(2),
      total_cash_in: totalCashIn.toFixed(2),
      total_cash_out: totalCashOut.toFixed(2),
      efectivo_esperado: efectivoEsperado.toFixed(2),
      efectivo_fisico: efectivoFisicoNum.toFixed(2),
      diferencia: diferencia.toFixed(2),
      estado: estado
    });

  } catch (error) {
    console.error('Error en el corte de caja:', error);
    res.status(500).json({ error: 'Error interno al procesar el corte de caja' });
  }
});
// ==========================================
// ENDPOINT: POST /api/client/request-withdrawal (Cliente solicita retiro con código)
// ==========================================
app.post('/api/client/request-withdrawal', verifyToken, async (req, res) => {
    const clientId = req.user.id;
    const { amount } = req.body;

    if (!amount || parseFloat(amount) <= 0) {
        return res.status(400).json({ success: false, error: "Monto inválido para el retiro" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Verificar saldo del cliente
        const userCheck = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [clientId]);
        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        const currentBalance = parseFloat(userCheck.rows[0].balance || 0);
        const withdrawAmount = parseFloat(amount);

        if (currentBalance < withdrawAmount) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: "Saldo insuficiente para solicitar este retiro" });
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

        res.json({
            success: true,
            code: withdrawalCode,
            message: "Código de retiro generado exitosamente"
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error al generar código de retiro:", error);
        res.status(500).json({ success: false, error: "Error interno al procesar la solicitud" });
    } finally {
        client.release();
    }
});

// ========================================== 
// ENDPOINT: POST /api/client/lookup-transaction (Consultar transacción exacta por Folio/ID)
// ==========================================
app.post('/api/client/lookup-transaction', verifyToken, async (req, res) => {
    const { folio } = req.body;

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
                COALESCE(m_owner.full_name, merchant_user.full_name, agent_user.full_name, 'Comercio Local') AS merchant_name,
                COALESCE(agent_user.full_name, 'Agente Autorizado') AS agent_name,
                sender.full_name AS sender_name,
                sender.phone_number AS sender_phone,
                receiver.full_name AS receiver_name,
                receiver.phone_number AS receiver_phone,
                client_user.full_name AS client_user_name,
                client_user.phone_number AS client_phone
            FROM transactions t
            LEFT JOIN merchants m ON t.merchant_id::text = m.id::text
            LEFT JOIN users m_owner ON m.owner_user_id::text = m_owner.id::text
            LEFT JOIN users merchant_user ON t.merchant_id::text = merchant_user.id::text
            LEFT JOIN users agent_user ON t.agent_id::text = agent_user.id::text
            LEFT JOIN users sender ON t.agent_id::text = sender.id::text
            LEFT JOIN users receiver ON t.client_id::text = receiver.id::text
            LEFT JOIN users client_user ON t.client_id::text = client_user.id::text
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
            formatType = 'Pago a Comercio';
        } else if (rawType.includes('REFUND')) {
            formatType = 'Devolución / Reembolso';
        } else if (rawType.includes('IN') && !rawType.includes('TRANSFER')) {
            formatType = 'Depósito (Cash-In)';
        } else if (rawType.includes('OUT') && !rawType.includes('TRANSFER')) {
            formatType = 'Retiro (Cash-Out)';
        }

        res.json({
            success: true,
            transaction: {
                transactionId: `TRX-${tx.id}`,
                type: formatType,
                agentName: tx.agent_name || 'Agente Autorizado',
                clientName: tx.client_user_name || 'Cliente Tiolito',
                clientPhone: tx.client_phone || 'N/A',
                merchantName: tx.merchant_name || 'Comercio Local',
                senderName: tx.sender_name || 'Emisor',
        senderPhone: tx.sender_phone || 'N/A',
                receiverName: tx.receiver_name || tx.client_user_name || 'Receptor',
                receiverPhone: tx.receiver_phone || tx.client_phone || 'N/A',
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
const LIMITE_POR_TRANSACCION = 2000.00;   // Máximo Q2,000.00 por operación
const LIMITE_DIARIO_ACUMULADO = 5000.00;  // Máximo Q5,000.00 al día por cliente
const LIMITE_MENSUAL_ACUMULADO = 25000.00; // Máximo Q25,000.00 al mes por cliente

// Middleware para validar límites de prevención de lavado de dinero y riesgo
async function validarLimitesAML(req, res, next) {
  try {
    // 1. Si la petición viene autenticada por token (como en /api/transfer), 
    // obtenemos el ID del usuario directamente del token (req.user.id)
    let clientId = req.user?.id;

    // 2. Si no hay token (por ejemplo, en Cash-In o Cash-Out), buscamos por el teléfono en el body
    if (!clientId) {
      const phone_number = req.body.phone_number || req.body.client_phone || req.body.telefono || req.body.phone;
      let userRes = await pool.query('SELECT id FROM users WHERE phone_number = $1', [phone_number]);
      if (userRes.rows.length === 0) {
        userRes = await pool.query('SELECT id FROM users WHERE telefono = $1', [phone_number]);
      }

      if (userRes.rows.length === 0) {
        return res.status(404).json({ error: 'Cliente no registrado en el sistema' });
      }
      clientId = userRes.rows[0].id;
    }

    const amount = req.body.amount ?? req.body.monto ?? req.body.withdrawAmount ?? 0;
    const montoNum = parseFloat(amount);

    // 3. Validar que el monto ingresado sea un número positivo
    if (isNaN(montoNum) || montoNum <= 0) {
      return res.status(400).json({ error: 'Ingresa un monto válido mayor a 0.' });
    }

    // 4. Validar límite individual (Q2,000.00)
    if (montoNum > LIMITE_POR_TRANSACCION) {
      const limiteFmt = LIMITE_POR_TRANSACCION.toFixed(2);
      return res.status(400).json({
        error: 'La operación excede el límite permitido de Q' + limiteFmt + ' por transacción.'
      });
    }

    // 5. Consultar acumulado diario y mensual de forma segura usando el clientId
    const queryAcumulados = `
      SELECT 
        COALESCE(SUM(CASE WHEN created_at::date = CURRENT_DATE THEN amount ELSE 0 END), 0) AS total_hoy,
        COALESCE(SUM(CASE WHEN EXTRACT(MONTH FROM created_at) = EXTRACT(MONTH FROM CURRENT_DATE) AND EXTRACT(YEAR FROM created_at) = EXTRACT(YEAR FROM CURRENT_DATE) THEN amount ELSE 0 END), 0) AS total_mes
      FROM transactions 
      WHERE client_id = $1
    `;

    const result = await pool.query(queryAcumulados, [clientId]);
    const row = result.rows[0] || { total_hoy: 0, total_mes: 0 };
    const totalHoy = parseFloat(row.total_hoy) || 0;
    const totalMes = parseFloat(row.total_mes) || 0;

    // 6. Validar límite diario (Q5,000.00)
    if (totalHoy + montoNum > LIMITE_DIARIO_ACUMULADO) {
      const diarioFmt = LIMITE_DIARIO_ACUMULADO.toFixed(2);
      const hoyFmt = totalHoy.toFixed(2);
      return res.status(400).json({
        error: 'La operación supera el límite diario permitido (Q' + diarioFmt + '). Acumulado hoy: Q' + hoyFmt + '.'
      });
    }

    // 7. Validar límite mensual (Q25,000.00)
    if (totalMes + montoNum > LIMITE_MENSUAL_ACUMULADO) {
      const mesFmt = LIMITE_MENSUAL_ACUMULADO.toFixed(2);
      const totalMesFmt = totalMes.toFixed(2);
      return res.status(400).json({
        error: 'La operación supera el límite mensual permitido (Q' + mesFmt + '). Acumulado este mes: Q' + totalMesFmt + '.'
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
app.get('/api/merchant/balance', verifyToken, async (req, res) => {
    try {
        const merchantId = req.user.id;
        const result = await pool.query('SELECT balance FROM users WHERE id = $1', [merchantId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Comercio no encontrado' });
        }
        
        res.json({ success: true, balance: result.rows[0].balance || '0.00' });
    } catch (error) {
        console.error("Error al obtener saldo del comercio:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 2. Generar orden de cobro (Código / QR dinámico)
// Memoria temporal para los cobros activos (o guárdalos en tu base de datos)
const activeCharges = {};

app.post('/api/merchant/generate-charge', verifyToken, async (req, res) => {
    try {
        const { amount } = req.body;
        const merchantId = req.user.id;

        if (!amount || parseFloat(amount) <= 0) {
            return res.status(400).json({ success: false, error: 'Ingresa un monto válido para cobrar' });
        }

        const chargeCode = 'CHG-' + Math.floor(100000 + Math.random() * 900000);
        
        // Guardamos el monto, el comercio y la hora de creación
        activeCharges[chargeCode] = {
            merchantId: merchantId,
            amount: parseFloat(amount),
            createdAt: Date.now() // 👈 Guardamos el timestamp actual
        };

        res.json({ 
            success: true, 
            charge_code: chargeCode,
            message: "Orden de cobro generada exitosamente (Expira en 5 minutos)"
        });
    } catch (error) {
        console.error("Error al generar orden de cobro:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/merchant/daily-report', async (req, res) => {
  try {
    const { merchantId } = req.query;
    
    // 💡 Convertimos el merchantId a número entero por seguridad
    const numericMerchantId = parseInt(merchantId, 10);

    if (isNaN(numericMerchantId)) {
      return res.status(400).json({ success: false, message: "ID de comercio inválido" });
    }

    const summaryQuery = `
      SELECT 
        COALESCE(SUM(amount), 0) as total_sales, 
        COUNT(*) as total_transactions
      FROM transactions 
      WHERE merchant_id = $1 
      AND DATE(created_at) = CURRENT_DATE;
    `;
    const summaryRes = await pool.query(summaryQuery, [numericMerchantId]);

    const txQuery = `
      SELECT t.*, u.full_name as client_name 
      FROM transactions t
      LEFT JOIN users u ON t.client_id = u.id
      WHERE t.merchant_id = $1 
      AND DATE(t.created_at) = CURRENT_DATE
      ORDER BY t.created_at DESC;
    `;
    const txRes = await pool.query(txQuery, [numericMerchantId]);

    res.json({
      success: true,
      summary: summaryRes.rows[0],
      transactions: txRes.rows
    });

  } catch (error) {
    console.error("Error al generar el corte del comercio:", error);
    res.status(500).json({ success: false, message: "Error al generar el reporte" });
  }
});

// ==========================================
// 3. Historial de ventas detallado del comercio
// ==========================================
app.get('/api/merchant/transactions', verifyToken, async (req, res) => {
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
            WHERE (t.merchant_id::text = $1::text OR t.agent_id::text = $1::text) 
              AND UPPER(t.type) IN ('MERCHANT-PAYMENT', 'REFUND', 'MERCHANT_PAYMENT')
            ORDER BY t.created_at DESC 
            LIMIT 50   
        `;

        const result = await pool.query(query, [merchantId]);

        res.json({ 
            success: true, 
            transactions: result.rows 
        });

    } catch (error) {
        console.error("Error al cargar ventas detalladas del comercio:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// ENDPOINT: POST /api/client/pay-merchant (Pago a comercio con Dos Tipos de Comercio y Límites)
// ==========================================
app.post('/api/client/pay-merchant', verifyToken, async (req, res) => {
    const clientId = req.user.id;
    const { charge_code } = req.body;

    if (!charge_code) {
        return res.status(400).json({ success: false, error: 'Ingresa o escanea un código de cobro válido.' });
    }

    // 1. VALIDAR QUE EL CÓDIGO EXISTA
    const chargeInfo = activeCharges[charge_code];
    if (!chargeInfo) {
        return res.status(400).json({ success: false, error: 'El código de cobro ya fue utilizado o es inválido.' });
    }

    // 🕒 VALIDAR EXPIRACIÓN (5 Minutos = 300,000 milisegundos)
    const CINCO_MINUTOS = 5 * 60 * 1000;
    if (Date.now() - chargeInfo.createdAt > CINCO_MINUTOS) {
        delete activeCharges[charge_code]; // Lo borramos por caducar
        return res.status(400).json({ success: false, error: 'El código de cobro ha expirado (más de 5 minutos).' });
    }

    const amountToPay = chargeInfo.amount; // Monto bruto que paga el cliente
    const merchantUserId = chargeInfo.merchantId;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 2. Obtener datos y tipo del comercio receptor desde la base de datos
        // Verificamos si tiene definido un merchant_type o tier ('small' o 'large'). Por defecto será 'small'.
        const merchantRes = await client.query(
            'SELECT id, full_name, merchant_type, tier FROM users WHERE id = $1', 
            [merchantUserId]
        );

        if (merchantRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Comercio receptor no encontrado.' });
        }

        const merchantData = merchantRes.rows[0];
        const merchantName = merchantData.full_name || 'Comercio Local';
        
        // Detectar tipo de comercio (soporta 'merchant_type' o 'tier')
        const merchantType = (merchantData.merchant_type || merchantData.tier || 'small').toLowerCase();

        // 🛡️ 3. APLICAR LÍMITES SEGÚN EL TIPO DE COMERCIO
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

        // Consultar acumulado diario del comercio en transacciones de hoy
        const ventasHoyRes = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS total_hoy FROM transactions 
             WHERE (merchant_id = $1 OR agent_id = $1) AND created_at::date = CURRENT_DATE`,
            [merchantUserId]
        );
        const totalVentasHoy = parseFloat(ventasHoyRes.rows[0].total_hoy || 0);

        if (totalVentasHoy + amountToPay > limiteMaxDaily) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                success: false, 
                error: `El comercio ha alcanzado su límite diario acumulado permitido (Máx. Q${limiteMaxDaily.toFixed(2)}).` 
            });
        }

        // 4. Obtener datos del cliente pagador
        const clientCheck = await client.query('SELECT id, full_name, phone_number, balance FROM users WHERE id = $1 FOR UPDATE', [clientId]);
        if (clientCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
        }
        const clientData = clientCheck.rows[0];
        const clientBalance = parseFloat(clientData.balance || 0);

        if (clientBalance < amountToPay) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, error: `Saldo insuficiente. Tienes Q${clientBalance} y necesitas Q${amountToPay}.` });
        }

        // 🚀 5. CÁLCULO DINÁMICO DE COMISIONES (2.0% pequeños / 2.5% grandes)
        const comisionTiolito = Number((amountToPay * tasaComision).toFixed(2));
        const montoNetoComercio = Number((amountToPay - comisionTiolito).toFixed(2));

        // 6. Descontar el monto total al cliente
        await client.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [amountToPay, clientId]);

        // 7. Acreditar el monto NETO al comercio
        await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [montoNetoComercio, merchantUserId]);
        try {
            await client.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2', [montoNetoComercio, merchantUserId]);
        } catch (eWallet) {}

        // 8. Acreditar el 100% de la comisión a Tiolito Admin automáticamente
        const adminRes = await client.query(
            "SELECT id FROM users WHERE role = 'admin' OR phone_number = '00000000' LIMIT 1"
        );
        if (adminRes.rows.length > 0) {
            const adminId = adminRes.rows[0].id;
            await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [comisionTiolito, adminId]);
            try {
                await client.query('UPDATE wallets SET balance = balance + $1 WHERE user_id = $2', [comisionTiolito, adminId]);
            } catch (eWalletAdmin) {}
        }

        // 9. Registrar la transacción en la base de datos
        const folioUnico = `TRX-${Date.now().toString().slice(-6)}-${Math.floor(1000 + Math.random() * 9000)}`;

        const txResult = await client.query(
            `INSERT INTO transactions (agent_id, client_id, merchant_id, amount, type, created_at) 
             VALUES ($1, $2, $3, $4, 'MERCHANT-PAYMENT', NOW()) RETURNING id, created_at`,
            [merchantUserId, clientId, merchantUserId, amountToPay]
        );

        await client.query('COMMIT');

        // 10. ANULAR EL CÓDIGO INMEDIATAMENTE
        delete activeCharges[charge_code];

        const receiptPayload = {
            folio: folioUnico,
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

        // 11. 🚀 NOTIFICAR EN TIEMPO REAL AL COMERCIO VÍA SOCKET
        io.to(`merchant_${merchantUserId}`).emit('payment_received', receiptPayload);

        // 12. Responder al cliente
        return res.json({
            success: true,
            transaction: receiptPayload
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al procesar pago a comercio:', error);
        return res.status(500).json({ success: false, error: error.message || 'Error al procesar el pago' });
    } finally {
        client.release();
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});