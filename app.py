"""
SAE Fácil — Backend Flask completo com segurança e painel admin
IA para Enfermagem | SPYNET Tecnologia
"""
from flask import Flask, jsonify, request, send_from_directory, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from datetime import datetime, timedelta
import os, hashlib, requests, json, uuid

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'saefacil-2026')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'saefacil-jwt-2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///saefacil.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'spynet2026admin')
ADMIN_EMAIL  = os.environ.get('ADMIN_EMAIL', 'salvecidossantos454@gmail.com')

# MODELOS
class Usuario(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    nome             = db.Column(db.String(100), nullable=False)
    email            = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash       = db.Column(db.String(256), nullable=False)
    categoria        = db.Column(db.String(50))
    coren            = db.Column(db.String(50))
    plano            = db.Column(db.String(20), default='trial')
    hotmart_id       = db.Column(db.String(100))
    plano_expira     = db.Column(db.DateTime)
    trial_expira     = db.Column(db.DateTime)
    bloqueado        = db.Column(db.Boolean, default=False)
    session_token    = db.Column(db.String(100))
    ultimo_ip        = db.Column(db.String(50))
    ultimo_acesso    = db.Column(db.DateTime)
    tentativas_login = db.Column(db.Integer, default=0)
    bloqueado_ate    = db.Column(db.DateTime)
    criado_em        = db.Column(db.DateTime, default=datetime.utcnow)
    saes             = db.relationship('SAE', backref='autor', lazy=True)

    def verificar_senha(self, senha):
        return self.senha_hash == hashlib.sha256(senha.encode()).hexdigest()

    def saes_mes(self):
        inicio = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
        return SAE.query.filter(SAE.usuario_id == self.id, SAE.criado_em >= inicio).count()

    def plano_ativo(self):
        if self.plano == 'trial':
            if self.trial_expira and datetime.utcnow() > self.trial_expira:
                self.plano = 'gratuito'
                db.session.commit()
                return False
            return True
        if self.plano == 'gratuito':
            return False
        if self.plano_expira and datetime.utcnow() > self.plano_expira:
            self.plano = 'gratuito'
            self.hotmart_id = None
            db.session.commit()
            return False
        return True

    def dias_trial_restantes(self):
        if self.plano == 'trial' and self.trial_expira:
            diff = (self.trial_expira - datetime.utcnow()).total_seconds()
            return max(0, int(diff / 86400) + 1)
        return 0

    def esta_bloqueado_temp(self):
        if self.bloqueado_ate and datetime.utcnow() < self.bloqueado_ate:
            return True
        return False

class SAE(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    usuario_id   = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    tipo         = db.Column(db.String(30))
    paciente     = db.Column(db.String(150))
    leito        = db.Column(db.String(100))
    diagnostico  = db.Column(db.String(200))
    texto_gerado = db.Column(db.Text)
    criado_em    = db.Column(db.DateTime, default=datetime.utcnow)

class WebhookLog(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    evento     = db.Column(db.String(100))
    email      = db.Column(db.String(120))
    hotmart_id = db.Column(db.String(100))
    payload    = db.Column(db.Text)
    processado = db.Column(db.Boolean, default=False)
    criado_em  = db.Column(db.DateTime, default=datetime.utcnow)

class LogAcesso(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer)
    email      = db.Column(db.String(120))
    ip         = db.Column(db.String(50))
    sucesso    = db.Column(db.Boolean, default=True)
    criado_em  = db.Column(db.DateTime, default=datetime.utcnow)

# MIGRAÇÃO
def migrar_banco():
    try:
        with db.engine.connect() as conn:
            for col, tipo in [
                ('hotmart_id', 'VARCHAR(100)'),
                ('plano_expira', 'TIMESTAMP'),
                ('bloqueado', 'BOOLEAN DEFAULT FALSE'),
                ('session_token', 'VARCHAR(100)'),
                ('ultimo_ip', 'VARCHAR(50)'),
                ('ultimo_acesso', 'TIMESTAMP'),
                ('tentativas_login', 'INTEGER DEFAULT 0'),
                ('bloqueado_ate', 'TIMESTAMP'),
                ('trial_expira', 'TIMESTAMP'),
            ]:
                try:
                    conn.execute(db.text(f'ALTER TABLE usuario ADD COLUMN IF NOT EXISTS {col} {tipo}'))
                except: pass
            for ddl in [
                """CREATE TABLE IF NOT EXISTS webhook_log (
                    id SERIAL PRIMARY KEY, evento VARCHAR(100), email VARCHAR(120),
                    hotmart_id VARCHAR(100), payload TEXT, processado BOOLEAN DEFAULT FALSE,
                    criado_em TIMESTAMP DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS log_acesso (
                    id SERIAL PRIMARY KEY, usuario_id INTEGER, email VARCHAR(120),
                    ip VARCHAR(50), sucesso BOOLEAN DEFAULT TRUE,
                    criado_em TIMESTAMP DEFAULT NOW())"""
            ]:
                try: conn.execute(db.text(ddl))
                except: pass
            conn.commit()
        print('[MIGRACAO] OK!')
    except Exception as e:
        print(f'[MIGRACAO] {e}')

# HELPERS
def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'desconhecido').split(',')[0].strip()

def registrar_acesso(uid, email, ok):
    try:
        db.session.add(LogAcesso(usuario_id=uid, email=email, ip=get_ip(), sucesso=ok))
        db.session.commit()
    except: pass

def validar_sessao():
    try:
        uid = int(get_jwt_identity())
        sid = get_jwt().get('sid', '')
        u = Usuario.query.get(uid)
        return u and not u.bloqueado and u.session_token == sid
    except: return False

# AUTENTICAÇÃO
@app.route('/api/auth/registro', methods=['POST'])
def registro():
    data = request.json
    if not data.get('email') or not data.get('senha') or not data.get('nome'):
        return jsonify({'erro': 'Dados incompletos'}), 400
    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({'erro': 'E-mail ja cadastrado'}), 400
    sid = str(uuid.uuid4())
    u = Usuario(nome=data['nome'], email=data['email'],
        senha_hash=hashlib.sha256(data['senha'].encode()).hexdigest(),
        categoria=data.get('categoria',''), coren=data.get('coren',''),
        plano='trial', trial_expira=datetime.utcnow() + timedelta(days=3),
        session_token=sid, ultimo_ip=get_ip(), ultimo_acesso=datetime.utcnow())
    db.session.add(u)
    db.session.commit()
    token = create_access_token(identity=str(u.id), additional_claims={'sid': sid})
    registrar_acesso(u.id, u.email, True)
    return jsonify({'token': token, 'nome': u.nome, 'plano': u.plano,
        'categoria': u.categoria, 'coren': u.coren,
        'trial_dias': u.dias_trial_restantes()}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    u = Usuario.query.filter_by(email=data.get('email','')).first()
    if not u:
        return jsonify({'erro': 'Credenciais invalidas'}), 401
    if u.bloqueado:
        return jsonify({'erro': 'Conta bloqueada. Entre em contato com o suporte.'}), 403
    if u.esta_bloqueado_temp():
        mins = int((u.bloqueado_ate - datetime.utcnow()).seconds / 60) + 1
        return jsonify({'erro': f'Conta bloqueada. Tente em {mins} minuto(s).'}), 403
    if not u.verificar_senha(data.get('senha','')):
        u.tentativas_login = (u.tentativas_login or 0) + 1
        if u.tentativas_login >= 5:
            u.bloqueado_ate = datetime.utcnow() + timedelta(minutes=15)
            u.tentativas_login = 0
            db.session.commit()
            registrar_acesso(u.id, u.email, False)
            return jsonify({'erro': 'Muitas tentativas. Bloqueado por 15 minutos.'}), 403
        db.session.commit()
        registrar_acesso(u.id, u.email, False)
        return jsonify({'erro': f'Credenciais invalidas. Tentativa {u.tentativas_login} de 5.'}), 401
    sid = str(uuid.uuid4())
    u.session_token = sid
    u.tentativas_login = 0
    u.bloqueado_ate = None
    u.ultimo_ip = get_ip()
    u.ultimo_acesso = datetime.utcnow()
    u.plano_ativo()
    db.session.commit()
    token = create_access_token(identity=str(u.id), additional_claims={'sid': sid})
    registrar_acesso(u.id, u.email, True)
    return jsonify({'token': token, 'nome': u.nome, 'plano': u.plano, 'categoria': u.categoria, 'coren': u.coren, 'trial_dias': u.dias_trial_restantes()})

# SAE
@app.route('/api/gerar-sae', methods=['POST'])
@jwt_required()
def gerar_sae():
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida. Faca login novamente.', 'sessao_invalida': True}), 401
    u = Usuario.query.get(int(get_jwt_identity()))
    if u.bloqueado:
        return jsonify({'erro': 'Conta bloqueada.'}), 403
    u.plano_ativo()
    if u.plano == 'gratuito':
        return jsonify({'erro': 'Seu período gratuito expirou. Assine o Plano Pro por R$ 67,00/mês para continuar.', 'limite': True, 'expirado': True}), 403
    data = request.json
    tipo = data.get('tipo', 'evolucao')
    pac = data.get('paciente', {})
    texto = _gerar_ia(tipo, pac)
    if not texto:
        return jsonify({'erro': 'Erro na IA'}), 500
    sae = SAE(usuario_id=u.id, tipo=tipo, paciente=pac.get('nome',''),
              leito=pac.get('leito',''), diagnostico=pac.get('diagnostico',''), texto_gerado=texto)
    db.session.add(sae)
    u.ultimo_acesso = datetime.utcnow()
    u.ultimo_ip = get_ip()
    db.session.commit()
    return jsonify({'texto': texto, 'id': sae.id})

@app.route('/api/saes', methods=['GET'])
@jwt_required()
def listar_saes():
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    uid = int(get_jwt_identity())
    saes = SAE.query.filter_by(usuario_id=uid).order_by(SAE.criado_em.desc()).limit(50).all()
    return jsonify([{'id': s.id, 'tipo': s.tipo, 'paciente': s.paciente, 'leito': s.leito,
        'diagnostico': s.diagnostico, 'texto': s.texto_gerado, 'data': s.criado_em.isoformat()} for s in saes])

@app.route('/api/stats')
@jwt_required()
def stats():
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    uid = int(get_jwt_identity())
    u = Usuario.query.get(uid)
    hoje = datetime.utcnow().date()
    inicio_mes = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
    u.plano_ativo()
    return jsonify({'hoje': SAE.query.filter(SAE.usuario_id==uid, db.func.date(SAE.criado_em)==hoje).count(),
        'mes': SAE.query.filter(SAE.usuario_id==uid, SAE.criado_em>=inicio_mes).count(),
        'total': SAE.query.filter_by(usuario_id=uid).count(),
        'plano': u.plano,
        'limite_mes': 9999,
        'trial_dias': u.dias_trial_restantes(),
        'trial_expira': u.trial_expira.isoformat() if u.trial_expira else None})

# PERFIL
@app.route('/api/auth/atualizar-perfil', methods=['PUT'])
@jwt_required()
def atualizar_perfil():
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    u = Usuario.query.get(int(get_jwt_identity()))
    data = request.json
    if data.get('nome'): u.nome = data['nome']
    if data.get('categoria'): u.categoria = data['categoria']
    if data.get('coren'): u.coren = data['coren']
    db.session.commit()
    return jsonify({'ok': True, 'nome': u.nome, 'categoria': u.categoria, 'coren': u.coren})

@app.route('/api/auth/trocar-senha', methods=['POST'])
@jwt_required()
def trocar_senha():
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    u = Usuario.query.get(int(get_jwt_identity()))
    data = request.json
    if not u.verificar_senha(data.get('senha_atual','')):
        return jsonify({'erro': 'Senha atual incorreta'}), 400
    nova = data.get('senha_nova','')
    if len(nova) < 6:
        return jsonify({'erro': 'Nova senha deve ter minimo 6 caracteres'}), 400
    u.senha_hash = hashlib.sha256(nova.encode()).hexdigest()
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/auth/recuperar-senha', methods=['POST'])
def recuperar_senha():
    import secrets, string
    data = request.json
    email = data.get('email','').lower().strip()
    u = Usuario.query.filter_by(email=email).first()
    if u:
        nova = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        u.senha_hash = hashlib.sha256(nova.encode()).hexdigest()
        db.session.commit()
        print(f'[SENHA] Nova senha para {email}: {nova}')
    return jsonify({'ok': True})

# WEBHOOK HOTMART
@app.route('/api/webhook/hotmart', methods=['POST'])
def webhook_hotmart():
    tok = os.environ.get('HOTMART_WEBHOOK_TOKEN', '')
    if tok and request.headers.get('X-Hotmart-Webhook-Token','') != tok:
        return jsonify({'erro': 'Token invalido'}), 401
    try: data = request.json or {}
    except: return jsonify({'erro': 'Payload invalido'}), 400
    evento = data.get('event', '')
    buyer = data.get('data', {}).get('buyer', {})
    subs = data.get('data', {}).get('subscription', {})
    purchase = data.get('data', {}).get('purchase', {})
    email = buyer.get('email', '').lower().strip()
    hid = subs.get('subscriber', {}).get('code', '') or purchase.get('transaction', '')
    print(f'[WEBHOOK] {evento} | {email}')
    log = WebhookLog(evento=evento, email=email, hotmart_id=hid, payload=json.dumps(data, ensure_ascii=False)[:2000])
    db.session.add(log)
    u = Usuario.query.filter_by(email=email).first()
    if evento in ('PURCHASE_APPROVED', 'PURCHASE_COMPLETE'):
        if u:
            u.plano = 'pro'
            u.hotmart_id = hid
            u.plano_expira = datetime.utcnow() + timedelta(days=35)
            log.processado = True
            print(f'[WEBHOOK] PRO ativado: {email}')
    elif evento in ('PURCHASE_CANCELED', 'PURCHASE_REFUNDED', 'SUBSCRIPTION_CANCELLATION', 'PURCHASE_CHARGEBACK'):
        if u:
            u.plano = 'gratuito'
            u.hotmart_id = None
            u.plano_expira = None
            log.processado = True
    db.session.commit()
    return jsonify({'status': 'ok', 'evento': evento}), 200

# ADMIN ROTAS
def check_admin(s): return s == ADMIN_SECRET

@app.route('/api/admin/listar-usuarios/<secret>')
def listar_usuarios(secret):
    if not check_admin(secret): return 'Sem permissao', 403
    users = Usuario.query.order_by(Usuario.criado_em.desc()).all()
    return jsonify([{'id': u.id, 'nome': u.nome, 'email': u.email, 'coren': u.coren,
        'categoria': u.categoria, 'plano': u.plano, 'bloqueado': u.bloqueado,
        'saes_mes': u.saes_mes(), 'ultimo_ip': u.ultimo_ip,
        'ultimo_acesso': u.ultimo_acesso.isoformat() if u.ultimo_acesso else None,
        'criado_em': u.criado_em.isoformat() if u.criado_em else None,
        'plano_expira': u.plano_expira.isoformat() if u.plano_expira else None} for u in users])

@app.route('/api/admin/ativar-pro/<secret>/<email>')
def ativar_pro_url(secret, email):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    u.plano = 'pro'; u.plano_expira = datetime.utcnow() + timedelta(days=35); u.hotmart_id = 'manual'
    db.session.commit()
    return f'PRO ativado para {email}!'

@app.route('/api/admin/desativar-pro/<secret>/<email>')
def desativar_pro(secret, email):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    u.plano = 'gratuito'; u.plano_expira = None; u.hotmart_id = None
    db.session.commit()
    return f'Pro desativado para {email}'

@app.route('/api/admin/bloquear/<secret>/<email>')
def bloquear_usuario(secret, email):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    u.bloqueado = True; u.session_token = None
    db.session.commit()
    return f'{email} bloqueado!'

@app.route('/api/admin/desbloquear/<secret>/<email>')
def desbloquear_usuario(secret, email):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    u.bloqueado = False; u.tentativas_login = 0; u.bloqueado_ate = None
    db.session.commit()
    return f'{email} desbloqueado!'

@app.route('/api/admin/resetar-senha/<secret>/<email>/<nova_senha>')
def resetar_senha_admin(secret, email, nova_senha):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    u.senha_hash = hashlib.sha256(nova_senha.encode()).hexdigest()
    u.session_token = None; u.tentativas_login = 0; u.bloqueado_ate = None
    db.session.commit()
    return f'Senha de {email} redefinida para: {nova_senha}'

@app.route('/api/admin/excluir-usuario/<secret>/<email>')
def excluir_usuario(secret, email):
    if not check_admin(secret): return 'Sem permissao', 403
    u = Usuario.query.filter_by(email=email).first()
    if not u: return f'Usuario {email} nao encontrado', 404
    SAE.query.filter_by(usuario_id=u.id).delete()
    db.session.delete(u); db.session.commit()
    return f'Usuario {email} excluido!'

@app.route('/api/admin/logs-acesso/<secret>')
def logs_acesso(secret):
    if not check_admin(secret): return 'Sem permissao', 403
    logs = LogAcesso.query.order_by(LogAcesso.criado_em.desc()).limit(100).all()
    return jsonify([{'email': l.email, 'ip': l.ip, 'sucesso': l.sucesso, 'data': l.criado_em.isoformat()} for l in logs])

# ADMIN HTML
@app.route('/admin')
def admin_panel():
    html = open('/admin.html').read() if os.path.exists('/admin.html') else ADMIN_PAGE
    return render_template_string(html)

ADMIN_PAGE = """<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SAE Fácil Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0A2F5C;min-height:100vh}
.login{max-width:400px;margin:80px auto;background:#fff;border-radius:16px;padding:2rem}
.login h2{color:#0A2F5C;text-align:center;margin-bottom:1.5rem}
input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;margin-bottom:1rem;font-size:15px}
.btn{padding:10px 18px;border:none;border-radius:8px;font-size:13px;cursor:pointer;color:#fff;background:#0A2F5C}
.full{width:100%}.green{background:#1b5e20}.red{background:#c62828}.orange{background:#e65100}.sm{padding:5px 12px;font-size:12px;margin:2px}
.panel{max-width:1200px;margin:0 auto;padding:1rem}
.hdr{background:#0A2F5C;color:#fff;padding:1rem 2rem;display:flex;justify-content:space-between;align-items:center}
.card{background:#fff;border-radius:12px;padding:1.5rem;margin-bottom:1rem}
.card h3{color:#0A2F5C;margin-bottom:1rem;border-bottom:2px solid #4FC3F7;padding-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:#0A2F5C;color:#fff;padding:8px 10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:middle}tr:hover td{background:#f5f8ff}
.badge{padding:3px 10px;border-radius:99px;font-size:11px;font-weight:bold;display:inline-block}
.pro{background:#FFD54F;color:#0A2F5C}.gratis{background:#eee;color:#555}.bloq{background:#c62828;color:#fff}
.alert{padding:10px 16px;border-radius:8px;margin-bottom:1rem}.aok{background:#e8f5e9;color:#1b5e20}.aerr{background:#ffebee;color:#c62828}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000}
.mbox{background:#fff;border-radius:12px;padding:2rem;max-width:420px;margin:100px auto}
.mbox h3{margin-bottom:.75rem;color:#0A2F5C}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.row input{margin:0;flex:1}
</style></head>
<body>
<div id="lp">
  <div class="login"><h2>🔐 SAE Fácil Admin</h2>
  <input type="password" id="pw" placeholder="Senha admin" onkeydown="if(event.key==='Enter')login()">
  <button class="btn full" onclick="login()">Entrar</button>
  <div id="lerr" style="color:red;text-align:center;margin-top:10px"></div></div>
</div>
<div id="ap" style="display:none">
  <div class="hdr"><h1>⚕️ SAE Fácil — Admin</h1><button class="btn sm" onclick="sair()">Sair</button></div>
  <div class="panel">
    <div id="ab"></div>
    <div class="card">
      <h3>👥 Usuários <span id="tot" style="font-size:13px;color:#888"></span></h3>
      <div class="row" style="margin-bottom:1rem">
        <input type="text" id="bq" placeholder="Buscar nome ou email..." oninput="filtrar()">
        <button class="btn sm green" onclick="reload()">🔄</button>
      </div>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>Nome</th><th>Email</th><th>COREN</th><th>Plano</th><th>SAEs</th><th>Último acesso</th><th>IP</th><th>Ações</th></tr></thead>
        <tbody id="tb"></tbody>
      </table></div>
    </div>
    <div class="card">
      <h3>🔑 Resetar Senha</h3>
      <div class="row">
        <input type="text" id="er" placeholder="Email"><input type="text" id="ns" placeholder="Nova senha">
        <button class="btn orange sm" onclick="resetSenha()">Resetar</button>
      </div>
    </div>
    <div class="card">
      <h3>📋 Logs de Acesso</h3>
      <button class="btn sm" onclick="loadLogs()" style="margin-bottom:1rem">Carregar logs</button>
      <div style="overflow-x:auto"><table>
        <thead><tr><th>Email</th><th>IP</th><th>Status</th><th>Data</th></tr></thead>
        <tbody id="ltb"></tbody>
      </table></div>
    </div>
  </div>
</div>
<div id="modal" class="modal">
  <div class="mbox"><h3 id="mt"></h3><p id="mp" style="margin-bottom:1rem;color:#555"></p>
  <div class="row"><button class="btn green" id="mc">Confirmar</button><button class="btn red" onclick="closeM()">Cancelar</button></div>
  </div>
</div>
<script>
let S='',us=[];
function login(){S=document.getElementById('pw').value;
fetch('/api/admin/listar-usuarios/'+S).then(r=>{if(!r.ok)throw 0;return r.json()})
.then(d=>{us=d;document.getElementById('lp').style.display='none';document.getElementById('ap').style.display='block';render(d)})
.catch(()=>document.getElementById('lerr').textContent='Senha incorreta!');}
function sair(){S='';document.getElementById('lp').style.display='block';document.getElementById('ap').style.display='none';document.getElementById('pw').value='';}
function filtrar(){const q=document.getElementById('bq').value.toLowerCase();render(us.filter(u=>u.nome.toLowerCase().includes(q)||u.email.toLowerCase().includes(q)));}
function render(d){
document.getElementById('tot').textContent='('+d.length+' usuarios)';
document.getElementById('tb').innerHTML=d.map(u=>`<tr>
<td><strong>${u.nome}</strong></td><td style="font-size:12px">${u.email}</td><td style="font-size:12px">${u.coren||'—'}</td>
<td><span class="badge ${u.bloqueado?'bloq':u.plano==='pro'?'pro':'gratis'}">${u.bloqueado?'🔒 BLOQUEADO':u.plano==='pro'?'⭐ PRO':'Gratuito'}</span>
${u.plano_expira?'<br><small style="color:#888">exp:'+u.plano_expira.substring(0,10)+'</small>':''}</td>
<td style="text-align:center">${u.saes_mes}</td>
<td style="font-size:11px">${u.ultimo_acesso?u.ultimo_acesso.replace('T',' ').substring(0,16):'—'}</td>
<td style="font-size:11px">${u.ultimo_ip||'—'}</td>
<td>
${!u.bloqueado&&u.plano!=='pro'?`<button class="btn green sm" onclick="acao('ativar-pro','${u.email}','Ativar PRO para ${u.nome}?')">✅ Pro</button>`:''}
${u.plano==='pro'&&!u.bloqueado?`<button class="btn orange sm" onclick="acao('desativar-pro','${u.email}','Desativar PRO de ${u.nome}?')">⬇️ Pro</button>`:''}
${!u.bloqueado?`<button class="btn red sm" onclick="acao('bloquear','${u.email}','Bloquear ${u.nome}?')">🔒</button>`:`<button class="btn green sm" onclick="acao('desbloquear','${u.email}','Desbloquear ${u.nome}?')">🔓</button>`}
<button class="btn red sm" onclick="acao('excluir-usuario','${u.email}','EXCLUIR ${u.nome}?')">🗑️</button>
</td></tr>`).join('');}
function acao(tipo,email,msg){
document.getElementById('mt').textContent=msg;
document.getElementById('mp').textContent='Email: '+email;
document.getElementById('modal').style.display='block';
document.getElementById('mc').onclick=()=>{
fetch('/api/admin/'+tipo+'/'+S+'/'+encodeURIComponent(email)).then(r=>r.text())
.then(t=>{closeM();alerta(t,'ok');reload();});};}
function resetSenha(){
const e=document.getElementById('er').value.trim(),s=document.getElementById('ns').value.trim();
if(!e||!s||s.length<6)return alerta('Preencha email e senha (min 6 chars)!','err');
fetch('/api/admin/resetar-senha/'+S+'/'+encodeURIComponent(e)+'/'+encodeURIComponent(s))
.then(r=>r.text()).then(t=>{alerta(t,'ok');document.getElementById('er').value='';document.getElementById('ns').value='';});}
function loadLogs(){fetch('/api/admin/logs-acesso/'+S).then(r=>r.json()).then(ls=>{
document.getElementById('ltb').innerHTML=ls.map(l=>`<tr><td>${l.email}</td><td>${l.ip}</td>
<td><span class="badge ${l.sucesso?'pro':'bloq'}">${l.sucesso?'OK':'Falha'}</span></td>
<td style="font-size:11px">${l.data.replace('T',' ').substring(0,16)}</td></tr>`).join('');});}
function closeM(){document.getElementById('modal').style.display='none';}
function alerta(m,t){const b=document.getElementById('ab');b.innerHTML=`<div class="alert a${t}">${m}</div>`;setTimeout(()=>b.innerHTML='',5000);}
function reload(){fetch('/api/admin/listar-usuarios/'+S).then(r=>r.json()).then(d=>{us=d;filtrar();});}
setInterval(reload,30000);
</script></body></html>"""

# IA
def _gerar_ia(tipo, p):
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key: return None
    sedado = any(x in p.get('queixas','').upper() for x in ['SEDADO','SEDADA','IOT','INTUBADO','INTUBADA','VM ','INCONSCIENTE'])
    ctx = "ATENCAO: Paciente sedado/intubado. Nao use diagnosticos com relato verbal. Use dados objetivos." if sedado else ""
    prompts = {
        'evolucao': f"""Enfermeiro especialista SAE NANDA-I 2024-2026 NIC NOC. Gere EVOLUCAO SOAP completa.
{ctx}
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnostico: {p.get('diagnostico')}
SVs: {p.get('sv')} | Queixas: {p.get('queixas')} | Sistemas: {', '.join(p.get('sistemas',[]))}
Exames/Dispositivos: {p.get('exames')} | Alergias: {p.get('alergias','')} | Obs: {p.get('obs')}
Estrutura: EVOLUCAO DE ENFERMAGEM / Data Hora / S-O-A(NANDA codigo R/A E/P)-P(NIC min6 NOC min3) / Assinatura.""",
        'prescricao': f"""Enfermeiro especialista. Gere PRESCRICAO ENFERMAGEM NIC.
{ctx}
Paciente:{p.get('nome')}|Leito:{p.get('leito')}|Diag:{p.get('diagnostico')}|SVs:{p.get('sv')}|Aval:{p.get('queixas')}|Disp:{p.get('exames')}
Estrutura: PRESCRICAO / Data Turno / NANDA / min12 itens numerados / NOC / Assinatura.""",
        'passagem': f"""Enfermeiro especialista. Gere PASSAGEM PLANTAO SBAR.
{ctx}
Paciente:{p.get('nome')}|Leito:{p.get('leito')}|Diag:{p.get('diagnostico')}|SVs:{p.get('sv')}|Sit:{p.get('queixas')}|Disp:{p.get('exames')}
Estrutura: SBAR completo S(situacao) B(background comorbidades dispositivos) A(NANDA hemodinamica) R(prioridades alertas pendencias) / Assinatura.""",
        'nanda': f"""Especialista NANDA-I 2024-2026 NIC NOC. Gere 4 DIAGNOSTICOS por prioridade clinica.
{ctx}
Paciente:{p.get('nome')}|Leito:{p.get('leito')}|Diag:{p.get('diagnostico')}|SVs:{p.get('sv')}|Aval:{p.get('queixas')}|Disp:{p.get('exames')}
Para cada: Nome(NANDA codigo) Dominio/Classe | R/A fator | E/P caracteristicas | NIC atividades | NOC meta mensuravel / Assinatura."""
    }
    try:
        r = requests.post('https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 3000,
                  'messages': [{'role': 'user', 'content': prompts.get(tipo, prompts['evolucao'])}]}, timeout=30)
        return r.json()['content'][0]['text']
    except Exception as e:
        print(f'Erro IA: {e}')
        return None

# ROTAS ESTATICAS
@app.route('/favicon.ico')
def favicon(): return ('', 204)

@app.route('/')
def index(): return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(404)
def not_found(e): return send_from_directory(app.static_folder, 'index.html')

# INIT
with app.app_context():
    db.create_all()
    migrar_banco()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
