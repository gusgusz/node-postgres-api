require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Inicializando o app do express
const app = express();
const port = 5000;

// Middleware para lidar com o JSON no corpo da requisição
app.use(express.json());

// Permitir qualquer origem
app.use(cors());
// Conexão com o banco de dados PostgreSQL
const pool = new Pool({
  connectionString: process.env.DB_URL,
});

// Testando a conexão
pool.connect()
  .then(() => console.log('Conectado ao PostgreSQL'))
  .catch(err => console.error('Erro ao conectar ao PostgreSQL:', err));

// Middleware de autenticação JWT
const authMiddleware = (req, res, next) => {
  // Pegando o token do cabeçalho Authorization
  const token = req.headers['authorization'];

  // Verificando se o token foi fornecido
  if (!token) {
    console.error("Token não fornecido");
    return res.status(403).json({ message: 'Token de autenticação não fornecido.' });
  }

  // Verificando se o token tem o prefixo "Bearer"
  if (!token.startsWith('Bearer ')) {
    console.error("Token malformado. Esperado 'Bearer <token>'");
    return res.status(400).json({ message: 'Token malformado. Formato esperado: Bearer <token>' });
  }

  // Removendo o "Bearer " e deixando só o token
  const tokenStr = token.split(' ')[1];

  // Verificando se o token é vazio após a remoção do prefixo "Bearer"
  if (!tokenStr) {
    console.error("Token vazio após a remoção do prefixo 'Bearer'");
    return res.status(400).json({ message: 'Token malformado.' });
  }

  try {
    // Verificando o token usando o segredo
    const decoded = jwt.verify(tokenStr, process.env.JWT_SECRET);
    
    // Log para verificar o payload do token
    console.log("Token decodificado:", decoded);
    
    // Atribuindo o userId do token à requisição
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error("Erro ao verificar o token:", error);

    // Verificando se o erro foi devido ao token expirado
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expirado.' });
    }

    // Erro genérico de token inválido
    return res.status(401).json({ message: error  });
  }
};

// Função de registro de usuário
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Verifica se todos os campos foram preenchidos
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
  }

  try {
    const hashPassword = await bcrypt.hash(password, 10);  // Encriptando a senha

    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashPassword]
    );

    const user = result.rows[0];

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);

    return res.status(201).json({
      message: 'Usuário registrado com sucesso',
      token,
      userId: user.id,  // Incluindo o userId no retorno
    });
  } catch (error) {
    console.error('Erro ao registrar usuário:', error);
    return res.status(500).json({ message: 'Erro ao registrar usuário.' });
  }
});

// Função de login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    // Verificando a senha
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Senha incorreta.' });
    }

    // Gerando o token JWT
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);

    return res.status(200).json({
      message: 'Login bem-sucedido',
      token,
      userId: user.id,  // Incluindo o userId no retorno
    });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    return res.status(500).json({ message: 'Erro ao fazer login.' });
  }
});

// Função para adicionar um favorito
app.post('/api/favorites', authMiddleware, async (req, res) => {
  const { name, poke_id } = req.body;
  const userId = req.userId;


  if (!name || !poke_id) {
    return res.status(400).json({ message: 'O nome do pokemon favorito e ID é obrigatório.' });
  }

  try {
    // Verificando se o usuário já favoritou esse nome
    const result = await pool.query(
      'SELECT * FROM favorites WHERE user_id = $1 AND name = $2',
      [userId, name]
    );

    if (result.rows.length > 0) {
      return res.status(400).json({ message: 'Este item já foi favoritado.' });
    }

    // Adicionando o favorito
    const insertResult = await pool.query(
      'INSERT INTO favorites (user_id, name, poke_id) VALUES ($1, $2) RETURNING *',
      [userId, name]
    );

    return res.status(201).json({
      message: 'Favorito adicionado com sucesso.',
      userId,  // Incluindo o userId no retorno
      favorite: insertResult.rows[0],  // Retornando o favorito recém-criado
    });
  } catch (error) {
    console.error('Erro ao adicionar favorito:', error);
    return res.status(500).json({ message: 'Erro ao adicionar favorito.' });
  }
});

// Função para listar os favoritos
app.get('/api/favorites', authMiddleware, async (req, res) => {
  const userId = req.userId;

  try {
    const result = await pool.query('SELECT * FROM favorites WHERE user_id = $1', [userId]);

    return res.status(200).json({
      userId,  // Incluindo o userId no retorno
      favorites: result.rows,  // Retornando os favoritos do usuário
    });
  } catch (error) {
    console.error('Erro ao listar favoritos:', error);
    return res.status(500).json({ message: 'Erro ao listar favoritos.' });
  }
});

// Função para remover um favorito
app.delete('/api/favorites/:id', authMiddleware, async (req, res) => {
  const poke_id  = req.params.id ;
  const userId = req.userId;

  try {
    const result = await pool.query(
      'DELETE FROM favorites WHERE poke_id = $1 AND user_id = $2 RETURNING *',
      [id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Favorito não encontrado.' });
    }

    return res.status(200).json({
      message: 'Favorito removido com sucesso.',
      userId,  // Incluindo o userId no retorno
      favorite: result.rows[0],  // Retornando o favorito removido
    });
  } catch (error) {
    console.error('Erro ao remover favorito:', error);
    return res.status(500).json({ message: 'Erro ao remover favorito.' });
  }
});

// Iniciando o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
