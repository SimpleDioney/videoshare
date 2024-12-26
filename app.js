// app.js
import express from 'express'
import sqlite3 from 'sqlite3'
import multer from 'multer'
import path from 'path'
import { fileURLToPath } from 'url'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const db = new sqlite3.Database('videos.db')
const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta-forte'

// Middlewares básicos
app.use(cors())
app.use(express.json())
app.use('/uploads', express.static('uploads'))

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10000
})
app.use(limiter)

// Multer config
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, uniqueSuffix + path.extname(file.originalname))
  }
})

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['video/mp4', 'video/webm', 'video/quicktime']
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true)
  } else {
    cb(new Error('Tipo de arquivo inválido. Apenas MP4, WebM e QuickTime são permitidos.'))
  }
}

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 100 * 1024 * 1024 }
})

// Database setup
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT NOT NULL,
    description TEXT,
    filename TEXT NOT NULL,
    views INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    hashtags TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    user_id INTEGER,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(video_id) REFERENCES videos(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`)

  db.run(`CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    video_id INTEGER,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(video_id, user_id),
    FOREIGN KEY(video_id) REFERENCES videos(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`)

    db.run(`CREATE TABLE IF NOT EXISTS comment_likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(comment_id, user_id),
    FOREIGN KEY(comment_id) REFERENCES comments(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS comment_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comment_id INTEGER,
    user_id INTEGER,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(comment_id) REFERENCES comments(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
    )`)

    db.run(`CREATE TABLE IF NOT EXISTS followers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER,
    following_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES users(id),
    FOREIGN KEY(following_id) REFERENCES users(id)
    )`)
})

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ error: 'Token não fornecido' })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' })
    req.user = user
    next()
  })
}

// Helpers
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next)

// Rotas de Autenticação
app.post('/register', asyncHandler(async (req, res) => {
  const { username, email, password } = req.body

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios' })
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  db.run(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashedPassword],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'Usuário ou email já existe' })
        }
        return res.status(500).json({ error: err.message })
      }
      res.status(201).json({ message: 'Usuário criado com sucesso' })
    }
  )
}))

app.post('/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body
  
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) return res.status(500).json({ error: err.message })
      if (!user) return res.status(401).json({ error: 'Usuário não encontrado' })
  
      const validPassword = await bcrypt.compare(password, user.password)
      if (!validPassword) return res.status(401).json({ error: 'Senha inválida' })
  
      const token = jwt.sign(
        { id: user.id, username: user.username }, 
        JWT_SECRET, 
        { expiresIn: '24h' }
      )
  
      res.json({ 
        token, 
        username: user.username,
        id: user.id  // Adicionando ID do usuário
      })
    })
  }))

// Rotas protegidas
app.post('/videos', authenticateToken, upload.single('video'), asyncHandler(async (req, res) => {
    console.log('Recebendo upload:', req.file); // Log do arquivo
    console.log('Dados do formulário:', req.body); // Log dos dados do formulário
    
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const { title, description, hashtags } = req.body;
    const filename = req.file.filename;

    db.run(
        'INSERT INTO videos (title, description, filename, user_id, hashtags) VALUES (?, ?, ?, ?, ?)',
        [title, description, filename, req.user.id, hashtags],
        function(err) {
            if (err) {
                console.error('Erro ao inserir no banco:', err); // Log de erro do banco
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ 
                id: this.lastID,
                message: 'Vídeo enviado com sucesso'
            });
        }
    );
}));

app.get('/debug/videos', (req, res) => {
    db.all('SELECT * FROM videos', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/videos/:id/like', authenticateToken, asyncHandler(async (req, res) => {
  db.run(
    'INSERT OR IGNORE INTO likes (video_id, user_id) VALUES (?, ?)',
    [req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      
      if (this.changes === 0) {
        return res.status(400).json({ error: 'Você já curtiu este vídeo' })
      }

      db.run(
        'UPDATE videos SET likes = likes + 1 WHERE id = ?',
        [req.params.id],
        (err) => {
          if (err) return res.status(500).json({ error: err.message })
          res.json({ message: 'Like adicionado' })
        }
      )
    }
  )
}))

app.post('/videos/:id/comments', authenticateToken, asyncHandler(async (req, res) => {
  const { content } = req.body
  if (!content) return res.status(400).json({ error: 'Conteúdo é obrigatório' })

  db.run(
    'INSERT INTO comments (video_id, user_id, content) VALUES (?, ?, ?)',
    [req.params.id, req.user.id, content],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      res.status(201).json({ id: this.lastID, message: 'Comentário adicionado' })
    }
  )
}))

// Rotas públicas
app.get('/videos', asyncHandler(async (req, res) => {
  const { page = 1, limit = 10, search, hashtag } = req.query
  const offset = (page - 1) * limit

  let query = `
    SELECT v.*, u.username, 
           (SELECT COUNT(*) FROM comments WHERE video_id = v.id) as comment_count
    FROM videos v 
    JOIN users u ON v.user_id = u.id 
    WHERE 1=1
  `
  const params = []

  if (search) {
    query += ' AND (v.title LIKE ? OR v.description LIKE ?)'
    params.push(`%${search}%`, `%${search}%`)
  }

  if (hashtag) {
    query += ' AND v.hashtags LIKE ?'
    params.push(`%${hashtag}%`)
  }

  query += ' ORDER BY v.created_at DESC LIMIT ? OFFSET ?'
  params.push(limit, offset)

  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json(rows)
  })
}))

app.get('/videos/:id', asyncHandler(async (req, res) => {
    let userId = null;
    
    // Tenta extrair o ID do usuário do token, se existir
    if (req.headers.authorization) {
      const token = req.headers.authorization.split(' ')[1];
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (err) {
        // Token inválido, mas não retornamos erro pois a rota é pública
      }
    }
  
    db.get(
      `SELECT 
        v.*, 
        u.username,
        (SELECT COUNT(*) FROM comments WHERE video_id = v.id) as comment_count,
        (SELECT COUNT(*) FROM likes WHERE video_id = v.id AND user_id = ?) as user_liked
       FROM videos v 
       JOIN users u ON v.user_id = u.id 
       WHERE v.id = ?`,
      [userId, req.params.id],
      (err, video) => {
        if (err) return res.status(500).json({ error: err.message })
        if (!video) return res.status(404).json({ error: 'Vídeo não encontrado' })
        res.json(video)
      }
    )
  }))

app.get('/videos/:id/comments', asyncHandler(async (req, res) => {
    let userId = null;
    
    // Tenta extrair o ID do usuário do token, se existir
    if (req.headers.authorization) {
      const token = req.headers.authorization.split(' ')[1];
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (err) {
        // Token inválido, mas não retornamos erro pois a rota é pública
      }
    }
  
    db.all(
      `SELECT 
        c.*,
        u.username,
        (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id) as likes,
        (SELECT COUNT(*) FROM comment_replies WHERE comment_id = c.id) as replies_count,
        (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id AND user_id = ?) as user_liked
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.video_id = ?
       ORDER BY c.created_at DESC`,
      [userId, req.params.id],
      (err, comments) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json(comments)
      }
    )
  }))

// Profile and follower routes
app.get('/users/:id/profile', asyncHandler(async (req, res) => {
  db.get(
    `SELECT 
      u.id, u.username, u.created_at,
      (SELECT COUNT(*) FROM videos WHERE user_id = u.id) as video_count,
      (SELECT COUNT(*) FROM followers WHERE following_id = u.id) as followers_count,
      (SELECT COUNT(*) FROM followers WHERE follower_id = u.id) as following_count
    FROM users u
    WHERE u.id = ?`,
    [req.params.id],
    (err, profile) => {
      if (err) return res.status(500).json({ error: err.message })
      if (!profile) return res.status(404).json({ error: 'Usuário não encontrado' })
      res.json(profile)
    }
  )
}))

app.get('/users/:id/following', authenticateToken, asyncHandler(async (req, res) => {
    db.get(
      'SELECT COUNT(*) as following FROM followers WHERE follower_id = ? AND following_id = ?',
      [req.user.id, req.params.id],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ following: result.following > 0 })
      }
    )
  }))

app.get('/videos/:id/liked', authenticateToken, asyncHandler(async (req, res) => {
  db.get(
    'SELECT COUNT(*) as liked FROM likes WHERE video_id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message })
      res.json({ liked: result.liked > 0 })
    }
  )
}))

app.delete('/videos/:id/like', authenticateToken, asyncHandler(async (req, res) => {
  db.run(
    'DELETE FROM likes WHERE video_id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      
      db.run(
        'UPDATE videos SET likes = likes - 1 WHERE id = ?',
        [req.params.id],
        (err) => {
          if (err) return res.status(500).json({ error: err.message })
          res.json({ message: 'Like removido' })
        }
      )
    }
  )
}))

// Rota para contabilizar visualização
app.get('/videos/:id/view', asyncHandler(async (req, res) => {
    db.run(
      'UPDATE videos SET views = views + 1 WHERE id = ?',
      [req.params.id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ message: 'View contabilizada' })
      }
    )
  }))
  
  // Rota para buscar respostas de um comentário
  app.get('/comments/:id/replies', asyncHandler(async (req, res) => {
    db.all(
      `SELECT r.*, u.username 
       FROM comment_replies r
       JOIN users u ON r.user_id = u.id
       WHERE r.comment_id = ?
       ORDER BY r.created_at ASC`,
      [req.params.id],
      (err, replies) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json(replies)
      }
    )
  }))
  
  // Rota para adicionar resposta a um comentário
  app.post('/comments/:id/replies', authenticateToken, asyncHandler(async (req, res) => {
    const { content } = req.body
    if (!content) return res.status(400).json({ error: 'Conteúdo é obrigatório' })
  
    db.run(
      'INSERT INTO comment_replies (comment_id, user_id, content) VALUES (?, ?, ?)',
      [req.params.id, req.user.id, content],
      function(err) {
        if (err) return res.status(500).json({ error: err.message })
        
        // Retornar a resposta completa com o username
        db.get(
          `SELECT r.*, u.username 
           FROM comment_replies r
           JOIN users u ON r.user_id = u.id
           WHERE r.id = ?`,
          [this.lastID],
          (err, reply) => {
            if (err) return res.status(500).json({ error: err.message })
            res.status(201).json(reply)
          }
        )
      }
    )
  }))
  
  // Rota para verificar status do like em um vídeo
  app.get('/videos/:id/like-status', authenticateToken, asyncHandler(async (req, res) => {
    db.get(
      'SELECT COUNT(*) as liked FROM likes WHERE video_id = ? AND user_id = ?',
      [req.params.id, req.user.id],
      (err, result) => {
        if (err) return res.status(500).json({ error: err.message })
        res.json({ liked: result.liked > 0 })
      }
    )
  }))

// Removendo like do comentário
app.delete('/comments/:id/like', authenticateToken, asyncHandler(async (req, res) => {
  db.run(
    'DELETE FROM comment_likes WHERE comment_id = ? AND user_id = ?',
    [req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      res.json({ unliked: this.changes > 0 })
    }
  )
}))

// Comment interaction routes
app.post('/comments/:id/replies', authenticateToken, asyncHandler(async (req, res) => {
  const { content } = req.body
  if (!content) return res.status(400).json({ error: 'Conteúdo é obrigatório' })

  db.run(
    'INSERT INTO comment_replies (comment_id, user_id, content) VALUES (?, ?, ?)',
    [req.params.id, req.user.id, content],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      res.status(201).json({ id: this.lastID })
    }
  )
}))

app.post('/comments/:id/like', authenticateToken, asyncHandler(async (req, res) => {
  db.run(
    'INSERT OR IGNORE INTO comment_likes (comment_id, user_id) VALUES (?, ?)',
    [req.params.id, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message })
      res.json({ liked: this.changes > 0 })
    }
  )
}))

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack)
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ 
      error: 'Erro no upload do arquivo',
      details: err.message 
    })
  }
  res.status(500).json({ error: 'Erro interno do servidor' })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`))