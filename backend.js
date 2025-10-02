// backend.js - Versão Servidor Local
import express from 'express';
import fs from 'fs/promises'; // Para ler e escrever arquivos
import bcrypt from 'bcrypt';
import cors from 'cors';

const app = express();
// A porta será definida pelo ambiente do Render/Heroku ou será 3000 se rodar localmente
const PORT = process.env.PORT || 3000;
const DB_PATH = './db.json'; // Alterado para o caminho relativo correto

// Middlewares para permitir CORS e para que o Express entenda JSON
app.use(cors());
app.use(express.json());

// ---- ROTA DE CADASTRO ----
app.post('/cadastro', async (req, res) => {
    const { usuario, email, senha } = req.body;
    console.log(`[INFO] Recebida requisição de cadastro para o email: ${email}`);
    try {
        const dbRaw = await fs.readFile(DB_PATH, 'utf-8');
        const usuarios = JSON.parse(dbRaw);
        const usuarioExistente = usuarios.find(u => u.email === email);
        if (usuarioExistente) {
            return res.status(409).json({ mensagem: 'Este email já está em uso.' });
        }
        const saltRounds = 10;
        const senhaHasheada = await bcrypt.hash(senha, saltRounds);
        const novoUsuario = { id: Date.now(), usuario, email, senha: senhaHasheada };
        usuarios.push(novoUsuario);
        await fs.writeFile(DB_PATH, JSON.stringify(usuarios, null, 2));
        console.log(`[OK] Usuário ${usuario} cadastrado com sucesso.`);
        res.status(201).json({ mensagem: `Usuário ${usuario} cadastrado com sucesso!` });
    } catch (error) {
        console.error('[ERRO] Falha ao processar cadastro:', error);
        res.status(500).json({ mensagem: 'Erro interno no servidor.' });
    }
});

// ---- ROTA DE LOGIN ----
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;
    console.log(`[INFO] Recebida tentativa de login para o email: ${email}`);
    try {
        const dbRaw = await fs.readFile(DB_PATH, 'utf-8');
        const usuarios = JSON.parse(dbRaw);
        const usuario = usuarios.find(u => u.email === email);
        if (!usuario) {
            return res.status(401).json({ mensagem: 'Email ou senha inválidos.' });
        }
        const senhaCorreta = await bcrypt.compare(senha, usuario.senha);
        if (!senhaCorreta) {
            return res.status(401).json({ mensagem: 'Email ou senha inválidos.' });
        }
        console.log(`[OK] Usuário ${usuario.usuario} logado com sucesso.`);
        const { senha: _, ...dadosUsuario } = usuario;
        res.status(200).json({ mensagem: 'Login bem-sucedido!', usuario: dadosUsuario });
    } catch (error) {
        console.error('[ERRO] Falha ao processar login:', error);
        res.status(500).json({ mensagem: 'Erro interno no servidor.' });
    }
});

// ---- ROTA PARA ATUALIZAR O PERFIL (FOTO/BIO) ----
app.patch('/perfil/:id', async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    const { foto, bio } = req.body;
    console.log(`[INFO] Recebida requisição para atualizar perfil do usuário ID: ${userId}`);
    try {
        const dbRaw = await fs.readFile(DB_PATH, 'utf-8');
        let usuarios = JSON.parse(dbRaw);
        const userIndex = usuarios.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }
        if (foto) {
            usuarios[userIndex].foto = foto;
        }
        if (bio) {
            usuarios[userIndex].bio = bio;
            console.log(`[INFO] Bio do usuário ${usuarios[userIndex].usuario} atualizada.`);
        }
        await fs.writeFile(DB_PATH, JSON.stringify(usuarios, null, 2));
        const { senha: _, ...dadosUsuario } = usuarios[userIndex];
        res.status(200).json({ mensagem: 'Perfil atualizado com sucesso!', usuario: dadosUsuario });
    } catch (error) {
        console.error('[ERRO] Falha ao atualizar perfil:', error);
        res.status(500).json({ mensagem: 'Erro interno no servidor.' });
    }
});

// ---- INICIA O SERVIDOR ----
app.listen(PORT, () => {
    console.log(`[OK] Servidor rodando na porta ${PORT}`);
    console.log('Aguardando requisições...');
});