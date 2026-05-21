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
            # Só expira se tiver trial_expira definido
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


# MODELO — Dispositivos do paciente
class Dispositivo(db.Model):
    __tablename__ = 'dispositivo'
    id         = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    paciente   = db.Column(db.String(150))
    leito      = db.Column(db.String(50))
    nome       = db.Column(db.String(100), nullable=False)
    data_insercao = db.Column(db.String(20))
    observacao = db.Column(db.String(300))
    ativo      = db.Column(db.Boolean, default=True)
    criado_em  = db.Column(db.DateTime, default=datetime.utcnow)

# MODELO — Pendências do turno
class Pendencia(db.Model):
    __tablename__ = 'pendencia'
    id         = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    paciente   = db.Column(db.String(150))
    leito      = db.Column(db.String(50))
    descricao  = db.Column(db.String(500), nullable=False)
    resolvida  = db.Column(db.Boolean, default=False)
    criado_em  = db.Column(db.DateTime, default=datetime.utcnow)

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
                    criado_em TIMESTAMP DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS dispositivo (
                    id SERIAL PRIMARY KEY, usuario_id INTEGER, paciente VARCHAR(150),
                    leito VARCHAR(50), nome VARCHAR(100) NOT NULL,
                    data_insercao VARCHAR(20), observacao VARCHAR(300),
                    ativo BOOLEAN DEFAULT TRUE,
                    criado_em TIMESTAMP DEFAULT NOW())""",
                """CREATE TABLE IF NOT EXISTS pendencia (
                    id SERIAL PRIMARY KEY, usuario_id INTEGER, paciente VARCHAR(150),
                    leito VARCHAR(50), descricao VARCHAR(500) NOT NULL,
                    resolvida BOOLEAN DEFAULT FALSE,
                    criado_em TIMESTAMP DEFAULT NOW())"""
            ]:
                try: conn.execute(db.text(ddl))
                except: pass
            # Adicionar campo cid_codigo na tabela sae se nao existir
            try:
                conn.execute(db.text("ALTER TABLE sae ADD COLUMN IF NOT EXISTS cid_codigo VARCHAR(20)"))
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
        plano='gratuito', trial_expira=None,
        session_token=sid, ultimo_ip=get_ip(), ultimo_acesso=datetime.utcnow())
    db.session.add(u)
    db.session.commit()
    # Verifica se ja tem pagamento aprovado na Hotmart para esse email
    log_pago = WebhookLog.query.filter_by(email=data['email'].lower().strip(), processado=False).filter(
        WebhookLog.evento.in_(['PURCHASE_APPROVED','PURCHASE_COMPLETE','SUBSCRIPTION_ACTIVATED'])
    ).first()
    if log_pago:
        u.plano = 'pro'
        u.hotmart_id = log_pago.hotmart_id
        u.plano_expira = datetime.utcnow() + timedelta(days=35)
        u.trial_expira = None
        log_pago.processado = True
        db.session.commit()
        print(f'[REGISTRO] PRO ativado automaticamente para {u.email}')
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
              leito=pac.get('leito',''), diagnostico=pac.get('diagnostico',''),
              texto_gerado=texto)
    # Salvar cid_codigo se o modelo suportar (migração segura)
    try:
        if hasattr(sae, 'cid_codigo'):
            sae.cid_codigo = pac.get('cid_codigo', '')
    except: pass
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
        'tem_trial': u.trial_expira is not None,
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
    if evento in ('PURCHASE_APPROVED', 'PURCHASE_COMPLETE', 'SUBSCRIPTION_ACTIVATED', 
                    'PURCHASE_BILLET_PRINTED', 'SUBSCRIPTION_REACTIVATED'):
        if u:
            u.plano = 'pro'
            u.hotmart_id = hid
            u.plano_expira = datetime.utcnow() + timedelta(days=35)
            u.trial_expira = None
            log.processado = True
            print(f'[WEBHOOK] PRO ativado: {email}')
        else:
            # Usuario nao cadastrado ainda — salva o log para ativar quando cadastrar
            print(f'[WEBHOOK] Usuario {email} nao encontrado — aguardando cadastro')
            log.processado = False
    elif evento in ('PURCHASE_CANCELED', 'PURCHASE_REFUNDED', 'SUBSCRIPTION_CANCELLATION', 
                    'PURCHASE_CHARGEBACK', 'SUBSCRIPTION_INACTIVE'):
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
    u.session_token = None
    u.bloqueado = True
    db.session.commit()
    SAE.query.filter_by(usuario_id=u.id).delete()
    db.session.delete(u)
    db.session.commit()
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


# CID-10 GERAL — base ampliada pesquisável por autocomplete
CID10_BASE = [
    # RESPIRATÓRIO
    {"codigo":"J00","descricao":"Nasofaringite aguda (resfriado comum)"},
    {"codigo":"J06.9","descricao":"Infecção aguda das vias aéreas superiores não especificada"},
    {"codigo":"J12.9","descricao":"Pneumonia viral não especificada"},
    {"codigo":"J15.9","descricao":"Pneumonia bacteriana não especificada"},
    {"codigo":"J18.0","descricao":"Broncopneumonia não especificada"},
    {"codigo":"J18.9","descricao":"Pneumonia não especificada"},
    {"codigo":"J20.9","descricao":"Bronquite aguda não especificada"},
    {"codigo":"J22","descricao":"Infecção aguda não especificada das vias aéreas inferiores"},
    {"codigo":"J43.9","descricao":"Enfisema pulmonar não especificado"},
    {"codigo":"J44.0","descricao":"DPOC com infecção respiratória aguda"},
    {"codigo":"J44.1","descricao":"DPOC com exacerbação aguda (DPOC exacerbada)"},
    {"codigo":"J44.9","descricao":"DPOC não especificada"},
    {"codigo":"J45.0","descricao":"Asma predominantemente alérgica"},
    {"codigo":"J45.1","descricao":"Asma não alérgica"},
    {"codigo":"J45.9","descricao":"Asma não especificada"},
    {"codigo":"J46","descricao":"Estado de mal asmático (status asmaticus)"},
    {"codigo":"J47","descricao":"Bronquiectasia"},
    {"codigo":"J80","descricao":"Síndrome do desconforto respiratório agudo (SARA)"},
    {"codigo":"J81","descricao":"Edema pulmonar agudo"},
    {"codigo":"J84.1","descricao":"Outras doenças pulmonares intersticiais com fibrose"},
    {"codigo":"J85.2","descricao":"Abscesso de pulmão"},
    {"codigo":"J90","descricao":"Derrame pleural"},
    {"codigo":"J93.1","descricao":"Pneumotórax espontâneo"},
    {"codigo":"J96.0","descricao":"Insuficiência respiratória aguda"},
    {"codigo":"J96.1","descricao":"Insuficiência respiratória crônica"},
    {"codigo":"J98.1","descricao":"Colapso pulmonar (atelectasia)"},
    {"codigo":"U07.1","descricao":"COVID-19"},
    # CARDIOVASCULAR
    {"codigo":"I10","descricao":"Hipertensão arterial essencial (HAS)"},
    {"codigo":"I11.0","descricao":"Cardiopatia hipertensiva com insuficiência cardíaca"},
    {"codigo":"I20.0","descricao":"Angina instável"},
    {"codigo":"I20.9","descricao":"Angina pectoris não especificada"},
    {"codigo":"I21.0","descricao":"IAM com supra de ST da parede anterior"},
    {"codigo":"I21.1","descricao":"IAM com supra de ST da parede inferior"},
    {"codigo":"I21.4","descricao":"IAM sem supra de ST (IAMSST)"},
    {"codigo":"I21.9","descricao":"Infarto agudo do miocárdio não especificado (IAM)"},
    {"codigo":"I22.9","descricao":"IAM recorrente não especificado"},
    {"codigo":"I25.1","descricao":"Cardiopatia aterosclerótica"},
    {"codigo":"I26.9","descricao":"Embolia pulmonar sem cor pulmonale agudo (TEP)"},
    {"codigo":"I27.0","descricao":"Hipertensão pulmonar primária"},
    {"codigo":"I33.0","descricao":"Endocardite infecciosa aguda e subaguda"},
    {"codigo":"I34.0","descricao":"Regurgitação mitral"},
    {"codigo":"I35.0","descricao":"Estenose aórtica"},
    {"codigo":"I42.0","descricao":"Cardiomiopatia dilatada"},
    {"codigo":"I44.2","descricao":"Bloqueio atrioventricular total (BAVT)"},
    {"codigo":"I47.1","descricao":"Taquicardia supraventricular"},
    {"codigo":"I47.2","descricao":"Taquicardia ventricular"},
    {"codigo":"I48","descricao":"Fibrilação e flutter atrial (FA)"},
    {"codigo":"I49.0","descricao":"Fibrilação ventricular"},
    {"codigo":"I50.0","descricao":"Insuficiência cardíaca congestiva (ICC)"},
    {"codigo":"I50.1","descricao":"Insuficiência ventricular esquerda"},
    {"codigo":"I50.9","descricao":"Insuficiência cardíaca não especificada"},
    {"codigo":"I60.9","descricao":"Hemorragia subaracnóidea não especificada"},
    {"codigo":"I61.9","descricao":"Hemorragia intracerebral não especificada (AVC hemorrágico)"},
    {"codigo":"I63.9","descricao":"AVC isquêmico não especificado"},
    {"codigo":"I64","descricao":"AVC não especificado como hemorrágico ou isquêmico"},
    {"codigo":"I70.2","descricao":"Aterosclerose das artérias dos membros"},
    {"codigo":"I74.3","descricao":"Embolia e trombose das artérias dos membros inferiores"},
    {"codigo":"I80.2","descricao":"Flebite e tromboflebite de outros vasos profundos"},
    {"codigo":"I82.4","descricao":"Trombose venosa profunda (TVP) de veias dos membros inferiores"},
    # NEUROLÓGICO
    {"codigo":"G20","descricao":"Doença de Parkinson"},
    {"codigo":"G35","descricao":"Esclerose múltipla"},
    {"codigo":"G40.9","descricao":"Epilepsia não especificada"},
    {"codigo":"G41.0","descricao":"Estado de mal epiléptico tônico-clônico"},
    {"codigo":"G43.9","descricao":"Enxaqueca não especificada"},
    {"codigo":"G45.9","descricao":"Ataque isquêmico transitório (AIT) não especificado"},
    {"codigo":"G62.9","descricao":"Polineuropatia não especificada"},
    {"codigo":"G93.1","descricao":"Lesão cerebral anóxica"},
    {"codigo":"S06.0","descricao":"Concussão cerebral"},
    {"codigo":"S06.9","descricao":"Traumatismo cranioencefálico não especificado (TCE)"},
    # ENDÓCRINO / METABÓLICO
    {"codigo":"E03.9","descricao":"Hipotireoidismo não especificado"},
    {"codigo":"E05.0","descricao":"Bócio difuso com hipertireoidismo"},
    {"codigo":"E05.9","descricao":"Tireotoxicose não especificada (hipertireoidismo)"},
    {"codigo":"E10.1","descricao":"Diabetes mellitus tipo 1 com cetoacidose"},
    {"codigo":"E10.9","descricao":"Diabetes mellitus tipo 1 sem complicações"},
    {"codigo":"E11.0","descricao":"Diabetes mellitus tipo 2 com coma"},
    {"codigo":"E11.5","descricao":"Diabetes mellitus tipo 2 com complicações circulatórias periféricas"},
    {"codigo":"E11.9","descricao":"Diabetes mellitus tipo 2 sem complicações"},
    {"codigo":"E14.9","descricao":"Diabetes mellitus não especificado"},
    {"codigo":"E16.0","descricao":"Hipoglicemia induzida por insulina sem coma"},
    {"codigo":"E66.9","descricao":"Obesidade não especificada"},
    {"codigo":"E83.5","descricao":"Distúrbios do metabolismo do cálcio"},
    {"codigo":"E86","descricao":"Depleção de volume (desidratação)"},
    {"codigo":"E87.0","descricao":"Hiperosmolaridade e hipernatremia"},
    {"codigo":"E87.1","descricao":"Hiponatremia"},
    {"codigo":"E87.2","descricao":"Acidose"},
    {"codigo":"E87.3","descricao":"Alcalose"},
    {"codigo":"E87.5","descricao":"Hipercalemia"},
    {"codigo":"E87.6","descricao":"Hipocalemia"},
    {"codigo":"E87.7","descricao":"Hipervolemia"},
    # RENAL / UROLÓGICO
    {"codigo":"N00.9","descricao":"Síndrome nefrítica aguda não especificada"},
    {"codigo":"N04.9","descricao":"Síndrome nefrótica não especificada"},
    {"codigo":"N17.0","descricao":"Insuficiência renal aguda com necrose tubular"},
    {"codigo":"N17.9","descricao":"Insuficiência renal aguda não especificada (IRA)"},
    {"codigo":"N18.3","descricao":"Doença renal crônica estágio 3"},
    {"codigo":"N18.4","descricao":"Doença renal crônica estágio 4"},
    {"codigo":"N18.5","descricao":"Doença renal crônica estágio 5"},
    {"codigo":"N18.9","descricao":"Insuficiência renal crônica não especificada (IRC)"},
    {"codigo":"N20.0","descricao":"Calculose renal (nefrolitíase)"},
    {"codigo":"N39.0","descricao":"Infecção do trato urinário não especificada (ITU)"},
    {"codigo":"N40","descricao":"Hiperplasia da próstata"},
    # GASTROINTESTINAL / HEPÁTICO
    {"codigo":"K21.0","descricao":"Doença do refluxo gastroesofágico com esofagite"},
    {"codigo":"K25.9","descricao":"Úlcera gástrica não especificada"},
    {"codigo":"K26.9","descricao":"Úlcera duodenal não especificada"},
    {"codigo":"K29.7","descricao":"Gastrite não especificada"},
    {"codigo":"K35.2","descricao":"Apendicite aguda com peritonite"},
    {"codigo":"K40.9","descricao":"Hérnia inguinal não especificada"},
    {"codigo":"K56.6","descricao":"Outras obstruções intestinais e as não especificadas"},
    {"codigo":"K57.3","descricao":"Doença diverticular do cólon sem perfuração/abscesso"},
    {"codigo":"K70.3","descricao":"Cirrose hepática alcoólica"},
    {"codigo":"K72.0","descricao":"Insuficiência hepática aguda e subaguda"},
    {"codigo":"K74.6","descricao":"Cirrose hepática não especificada"},
    {"codigo":"K80.2","descricao":"Calculose vesicular com colecistite aguda (colelitíase)"},
    {"codigo":"K85.9","descricao":"Pancreatite aguda não especificada"},
    {"codigo":"K92.0","descricao":"Hematêmese"},
    {"codigo":"K92.1","descricao":"Melena / Hemorragia digestiva alta"},
    {"codigo":"K92.2","descricao":"Hemorragia gastrointestinal não especificada"},
    # INFECCIOSO / SÉPTICO
    {"codigo":"A04.9","descricao":"Infecção intestinal bacteriana não especificada"},
    {"codigo":"A09","descricao":"Diarreia e gastroenterite de origem infecciosa"},
    {"codigo":"A15.0","descricao":"Tuberculose pulmonar (TBC)"},
    {"codigo":"A41.0","descricao":"Sepse por Staphylococcus aureus"},
    {"codigo":"A41.5","descricao":"Sepse por outros microrganismos gram-negativos"},
    {"codigo":"A41.9","descricao":"Sepse não especificada"},
    {"codigo":"B20","descricao":"Doença pelo HIV com doenças infecciosas e parasitárias"},
    {"codigo":"B34.9","descricao":"Infecção viral não especificada"},
    {"codigo":"R57.2","descricao":"Choque séptico"},
    {"codigo":"R57.9","descricao":"Choque não especificado"},
    # ONCOLÓGICO
    {"codigo":"C18.9","descricao":"Neoplasia maligna do cólon não especificada"},
    {"codigo":"C34.9","descricao":"Neoplasia maligna do brônquio e do pulmão"},
    {"codigo":"C50.9","descricao":"Neoplasia maligna da mama não especificada"},
    {"codigo":"C61","descricao":"Neoplasia maligna da próstata"},
    {"codigo":"C67.9","descricao":"Neoplasia maligna da bexiga não especificada"},
    {"codigo":"C80.1","descricao":"Neoplasia maligna não especificada (câncer)"},
    {"codigo":"C91.0","descricao":"Leucemia linfoblástica aguda"},
    {"codigo":"C92.0","descricao":"Leucemia mieloide aguda"},
    {"codigo":"D64.9","descricao":"Anemia não especificada"},
    {"codigo":"Z51.1","descricao":"Quimioterapia para neoplasia"},
    {"codigo":"Z51.0","descricao":"Radioterapia"},
    # MUSCULOESQUELÉTICO
    {"codigo":"M05.9","descricao":"Artrite reumatoide soropositiva não especificada"},
    {"codigo":"M10.9","descricao":"Gota não especificada"},
    {"codigo":"M16.9","descricao":"Coxartrose (artrose do quadril) não especificada"},
    {"codigo":"M17.9","descricao":"Gonartrose (artrose do joelho) não especificada"},
    {"codigo":"M54.5","descricao":"Lombalgia (dor lombar)"},
    {"codigo":"M79.3","descricao":"Paniculite não especificada"},
    {"codigo":"S72.0","descricao":"Fratura do colo do fêmur"},
    {"codigo":"S82.2","descricao":"Fratura da diáfise da tíbia"},
    {"codigo":"T14.9","descricao":"Traumatismo não especificado"},
    # PELE
    {"codigo":"L03.1","descricao":"Celulite de outras partes dos membros (erisipela)"},
    {"codigo":"L89.0","descricao":"Úlcera de pressão estágio 1"},
    {"codigo":"L89.1","descricao":"Úlcera de pressão estágio 2"},
    {"codigo":"L89.2","descricao":"Úlcera de pressão estágio 3"},
    {"codigo":"L89.3","descricao":"Úlcera de pressão estágio 4"},
    {"codigo":"L89.9","descricao":"Úlcera de pressão não especificada (lesão por pressão)"},
    # PSIQUIÁTRICO
    {"codigo":"F03","descricao":"Demência não especificada"},
    {"codigo":"F10.2","descricao":"Síndrome de dependência ao álcool"},
    {"codigo":"F20.9","descricao":"Esquizofrenia não especificada"},
    {"codigo":"F32.9","descricao":"Episódio depressivo não especificado"},
    {"codigo":"F41.1","descricao":"Transtorno de ansiedade generalizada"},
    # PROCEDIMENTOS E OUTROS
    {"codigo":"Z03.9","descricao":"Observação e avaliação médica por razão não especificada"},
    {"codigo":"Z96.6","descricao":"Presença de implantes ortopédicos articulares (pós-artroplastia)"},
    {"codigo":"T39.1","descricao":"Intoxicação por paracetamol"},
    {"codigo":"T60.0","descricao":"Intoxicação por organofosforados e carbamatos"},
    {"codigo":"T71","descricao":"Asfixia"},
    {"codigo":"T79.3","descricao":"Infecção pós-traumática não especificada"},
    # DOENÇAS INFECCIOSAS / TROPICAIS (faltavam)
    {"codigo":"A90","descricao":"Dengue clássica (febre do dengue)"},
    {"codigo":"A91","descricao":"Febre hemorrágica do dengue"},
    {"codigo":"A97.0","descricao":"Dengue sem sinais de alarme"},
    {"codigo":"A97.1","descricao":"Dengue com sinais de alarme"},
    {"codigo":"A97.2","descricao":"Dengue grave"},
    {"codigo":"A92.0","descricao":"Infecção pelo vírus Chikungunya"},
    {"codigo":"A92.8","descricao":"Febre Zika"},
    {"codigo":"A16.2","descricao":"Tuberculose pulmonar sem confirmação bacteriológica"},
    {"codigo":"B54","descricao":"Malária não especificada"},
    {"codigo":"B50","descricao":"Malária por Plasmodium falciparum"},
    {"codigo":"B19.9","descricao":"Hepatite viral não especificada"},
    {"codigo":"B16","descricao":"Hepatite aguda tipo B"},
    {"codigo":"B17.1","descricao":"Hepatite aguda tipo C"},
    {"codigo":"B18.2","descricao":"Hepatite crônica tipo C"},
    {"codigo":"B15.9","descricao":"Hepatite A sem coma hepático"},
    {"codigo":"A01.0","descricao":"Febre tifoide"},
    {"codigo":"A02.0","descricao":"Enterite por Salmonella"},
    {"codigo":"A06.0","descricao":"Disenteria amebiana aguda"},
    {"codigo":"A37.0","descricao":"Coqueluche por Bordetella pertussis"},
    {"codigo":"A36.9","descricao":"Difteria não especificada"},
    {"codigo":"A80.9","descricao":"Poliomielite aguda não especificada"},
    {"codigo":"B05.9","descricao":"Sarampo sem complicações"},
    {"codigo":"B06.9","descricao":"Rubéola sem complicações"},
    {"codigo":"B26.9","descricao":"Caxumba (parotidite epidêmica) sem complicações"},
    {"codigo":"B01.9","descricao":"Catapora (varicela) sem complicações"},
    {"codigo":"B02.9","descricao":"Herpes zoster sem complicações"},
    {"codigo":"B00.9","descricao":"Infecção pelo herpes simplex não especificada"},
    {"codigo":"B37.0","descricao":"Candidíase da boca (muguet)"},
    {"codigo":"B37.3","descricao":"Candidíase da vulva e vagina"},
    {"codigo":"A60.0","descricao":"Infecção pelo herpesvírus nos órgãos genitais"},
    # DOENÇAS CRÔNICAS COMUNS (faltavam)
    {"codigo":"J30.1","descricao":"Rinite alérgica devida a pólen (rinite alérgica)"},
    {"codigo":"J30.4","descricao":"Rinite alérgica crônica"},
    {"codigo":"H10.1","descricao":"Conjuntivite aguda atópica (conjuntivite alérgica)"},
    {"codigo":"H10.0","descricao":"Conjuntivite mucopurulenta"},
    {"codigo":"K59.0","descricao":"Constipação intestinal"},
    {"codigo":"K58.9","descricao":"Síndrome do intestino irritável sem diarreia"},
    {"codigo":"K21.9","descricao":"Doença do refluxo gastroesofágico sem esofagite (DRGE)"},
    {"codigo":"K81.0","descricao":"Colecistite aguda"},
    {"codigo":"K81.1","descricao":"Colecistite crônica"},
    {"codigo":"I84.9","descricao":"Hemorroidas não especificadas"},
    {"codigo":"L50.9","descricao":"Urticária não especificada"},
    {"codigo":"L20.9","descricao":"Dermatite atópica não especificada"},
    {"codigo":"L30.9","descricao":"Dermatite não especificada"},
    {"codigo":"M54.4","descricao":"Lumbago com ciática"},
    {"codigo":"M54.2","descricao":"Cervicalgia"},
    {"codigo":"M75.1","descricao":"Síndrome do manguito rotador"},
    {"codigo":"G43.0","descricao":"Enxaqueca sem aura"},
    {"codigo":"G47.0","descricao":"Insônia"},
    {"codigo":"R51","descricao":"Cefaleia"},
    {"codigo":"R10.4","descricao":"Outras dores abdominais e as não especificadas"},
    {"codigo":"R11","descricao":"Náusea e vômitos"},
    {"codigo":"R50.9","descricao":"Febre não especificada"},
    {"codigo":"R05","descricao":"Tosse"},
    {"codigo":"R06.0","descricao":"Dispneia"},
    {"codigo":"R00.0","descricao":"Taquicardia não especificada"},
    {"codigo":"R00.1","descricao":"Bradicardia não especificada"},
    {"codigo":"R55","descricao":"Síncope e colapso"},
    {"codigo":"R41.3","descricao":"Outras amnésias (confusão mental)"},
    {"codigo":"R42","descricao":"Tontura e vertigem"},
    # OBSTETRÍCIA / GINECOLOGIA
    {"codigo":"O10.0","descricao":"Hipertensão essencial pré-existente na gravidez"},
    {"codigo":"O14.1","descricao":"Pré-eclâmpsia grave"},
    {"codigo":"O15.0","descricao":"Eclâmpsia na gravidez"},
    {"codigo":"O20.0","descricao":"Ameaça de aborto"},
    {"codigo":"O21.0","descricao":"Hiperemese gravídica leve"},
    {"codigo":"O24.4","descricao":"Diabetes mellitus gestacional"},
    {"codigo":"O42.9","descricao":"Rotura prematura de membranas não especificada"},
    {"codigo":"O60.0","descricao":"Trabalho de parto pré-termo sem parto"},
    {"codigo":"O80","descricao":"Parto único espontâneo"},
    {"codigo":"O82","descricao":"Parto por cesariana não especificado"},
    {"codigo":"N93.9","descricao":"Sangramento uterino e vaginal anormal não especificado"},
    {"codigo":"N94.6","descricao":"Dismenorreia não especificada"},
    # PEDIATRIA / NEONATAL
    {"codigo":"P07.1","descricao":"Outros recém-nascidos de baixo peso"},
    {"codigo":"P22.0","descricao":"Síndrome da angústia respiratória do recém-nascido (SARNN)"},
    {"codigo":"P36.9","descricao":"Sepse bacteriana do recém-nascido não especificada"},
    {"codigo":"J02.9","descricao":"Faringite aguda (amigdalite)"},
    {"codigo":"J03.9","descricao":"Amigdalite aguda não especificada"},
    {"codigo":"H66.9","descricao":"Otite média não especificada"},
    {"codigo":"H65.9","descricao":"Otite média não supurativa não especificada"},
    # SAÚDE MENTAL
    {"codigo":"F10.0","descricao":"Transtorno mental e comportamental por uso de álcool — intoxicação aguda"},
    {"codigo":"F11.2","descricao":"Síndrome de dependência a opiáceos"},
    {"codigo":"F19.2","descricao":"Síndrome de dependência a múltiplas drogas"},
    {"codigo":"F43.1","descricao":"Transtorno de estresse pós-traumático (TEPT)"},
    {"codigo":"F40.1","descricao":"Fobias sociais"},
    {"codigo":"F50.0","descricao":"Anorexia nervosa"},
    {"codigo":"F50.2","descricao":"Bulimia nervosa"},
    {"codigo":"F60.3","descricao":"Transtorno de personalidade borderline"},
    {"codigo":"F84.0","descricao":"Autismo infantil (TEA)"},
    {"codigo":"F90.0","descricao":"Distúrbio da atividade e da atenção (TDAH)"},
    # CIRÚRGICO / TRAUMA
    {"codigo":"S22.0","descricao":"Fratura de vértebra torácica"},
    {"codigo":"S32.0","descricao":"Fratura de vértebra lombar"},
    {"codigo":"S42.2","descricao":"Fratura da diáfise do úmero"},
    {"codigo":"S52.5","descricao":"Fratura da extremidade distal do rádio (Colles)"},
    {"codigo":"T20.3","descricao":"Queimadura de terceiro grau da cabeça e pescoço"},
    {"codigo":"T31.1","descricao":"Queimaduras que abrangem 10-19% da superfície corporal"},
    {"codigo":"T36.9","descricao":"Intoxicação por antibiótico sistêmico não especificado"},
    {"codigo":"T45.5","descricao":"Intoxicação por anticoagulantes"},
    {"codigo":"T50.9","descricao":"Intoxicação por outros medicamentos e substâncias"},
    {"codigo":"X84","descricao":"Lesão autoprovocada intencionalmente (tentativa de suicídio)"},
    # OUTROS COMUNS
    {"codigo":"E55.9","descricao":"Deficiência de vitamina D não especificada"},
    {"codigo":"E50.9","descricao":"Deficiência de vitamina A não especificada"},
    {"codigo":"D50.9","descricao":"Anemia por deficiência de ferro não especificada"},
    {"codigo":"D51.9","descricao":"Anemia por deficiência de vitamina B12 não especificada"},
    {"codigo":"D69.6","descricao":"Trombocitopenia não especificada"},
    {"codigo":"M32.9","descricao":"Lúpus eritematoso sistêmico não especificado (LES)"},
    {"codigo":"M34.9","descricao":"Esclerodermia não especificada"},
    {"codigo":"K90.0","descricao":"Doença celíaca"},
    {"codigo":"K50.9","descricao":"Doença de Crohn não especificada"},
    {"codigo":"K51.9","descricao":"Retocolite ulcerativa não especificada"},
    {"codigo":"N80.9","descricao":"Endometriose não especificada"},
    {"codigo":"N18.1","descricao":"Doença renal crônica estágio 1"},
    {"codigo":"I73.9","descricao":"Doença vascular periférica não especificada"},
    {"codigo":"E78.0","descricao":"Hipercolesterolemia pura (dislipidemia)"},
    {"codigo":"E78.5","descricao":"Hiperlipidemia não especificada"},
    {"codigo":"Z87.3","descricao":"História pessoal de doenças musculoesqueléticas"},
]

@app.route('/api/buscar-cid', methods=['GET'])
def buscar_cid():
    """Busca CID-10 por termo — retorna até 12 resultados para autocomplete"""
    termo = request.args.get('q', '').lower().strip()
    if not termo or len(termo) < 2:
        return jsonify([])
    resultado = []
    for item in CID10_BASE:
        if (termo in item['descricao'].lower() or termo in item['codigo'].lower()):
            resultado.append(item)
        if len(resultado) >= 12:
            break
    return jsonify(resultado)

# IA — MAPEAMENTO CLÍNICO E GERAÇÃO DE DOCUMENTOS
# ────────────────────────────────────────────────────────────
def _mapear_nanda_por_patologia(diag_completo):
    """Mapeia diagnóstico médico → NANDA prioritário + cuidados específicos.
    Resolve o problema de diagnósticos genéricos iguais para todos os pacientes."""
    d = diag_completo.lower()
    # RESPIRATÓRIO
    if any(x in d for x in ['asma','crise asmat','broncoespas','j45','j46','status asmat']):
        return {'nanda1':'Padrão respiratório ineficaz (NANDA 00032) — Domínio 4, Classe 4',
                'nanda2':'Troca de gases prejudicada (NANDA 00030) — Domínio 4, Classe 4',
                'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
                'plano':'posição Fowler 45°, broncodilatadores conforme prescrição, oximetria contínua (meta SpO2>95%), ausculta pulmonar 2/2h, nebulização conforme prescrição, observar uso musculatura acessória, evitar fatores desencadeantes, inaloterapia',
                'noc':'Estado respiratório: ventilação (0403) SpO2>95%; Controle de sintomas (1608); Nível de ansiedade (1211)'}
    if any(x in d for x in ['dpoc','doença pulmonar obstrutiva','j44','j43','enfisema']):
        return {'nanda1':'Troca de gases prejudicada (NANDA 00030) — Domínio 4, Classe 4',
                'nanda2':'Padrão respiratório ineficaz (NANDA 00032) — Domínio 4, Classe 4',
                'nanda3':'Intolerância à atividade (NANDA 00092) — Domínio 4, Classe 4',
                'plano':'posição semi-Fowler 30-45°, O2 controlado (atenção retenção CO2 meta SpO2 88-92%), fisioterapia respiratória, respiração com lábios franzidos, monitorar sonolência/confusão (retenção CO2), nebulização com broncodilatador',
                'noc':'Estado respiratório: troca gasosa (0402) SpO2 88-92%; Tolerância à atividade (0005); Autocontrole DPOC (3200)'}
    if any(x in d for x in ['pneumonia','j18','j15','j12']):
        return {'nanda1':'Troca de gases prejudicada (NANDA 00030) — Domínio 4, Classe 4',
                'nanda2':'Hipertermia (NANDA 00007) — Domínio 11, Classe 6',
                'nanda3':'Padrão respiratório ineficaz (NANDA 00032) — Domínio 4, Classe 4',
                'plano':'cabeceira 30-45°, antibioticoterapia rigorosa no horário, controle temperatura 4/4h, hidratação, incentivar expectoração, fisioterapia respiratória, coleta culturas conforme prescrição',
                'noc':'Estado respiratório: troca gasosa (0402); Termorregulação (0800); Controle infecção (1924)'}
    if any(x in d for x in ['insuficiência respiratória','j96','sara','sdra']):
        return {'nanda1':'Troca de gases prejudicada (NANDA 00030) — Domínio 4, Classe 4',
                'nanda2':'Padrão respiratório ineficaz (NANDA 00032) — Domínio 4, Classe 4',
                'nanda3':'Risco de aspiração (NANDA 00039) — Domínio 11, Classe 2',
                'plano':'monitorar gasometria e oximetria, cabeceira 30-45°, O2 conforme prescrição, preparar material IOT, aspiração vias aéreas se necessário, monitorar nível consciência',
                'noc':'Estado respiratório: troca gasosa (0402); Permeabilidade vias aéreas (0410); Nível consciência (0912)'}
    # CARDIOVASCULAR
    if any(x in d for x in ['infarto','iam','i21','supra de st','iamsst']):
        return {'nanda1':'Débito cardíaco diminuído (NANDA 00029) — Domínio 4, Classe 4',
                'nanda2':'Dor aguda (NANDA 00132) — Domínio 12, Classe 1',
                'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
                'plano':'repouso absoluto 12-24h, monitoração cardíaca contínua, acesso venoso calibroso, controle da dor (EVA), administrar antiagregantes/anticoagulantes, ECG seriado, enzimas cardíacas conforme horário, O2 se SpO2<95%',
                'noc':'Estado cardíaco (0414); Nível de dor (2102); Nível de ansiedade (1211)'}
    if any(x in d for x in ['insuficiência cardíaca','icc','i50']):
        return {'nanda1':'Débito cardíaco diminuído (NANDA 00029) — Domínio 4, Classe 4',
                'nanda2':'Excesso de volume de líquidos (NANDA 00026) — Domínio 2, Classe 5',
                'nanda3':'Intolerância à atividade (NANDA 00092) — Domínio 4, Classe 4',
                'plano':'MMII elevados 30°, restrição hídrica conforme prescrição, diurese rigorosa (balanço hídrico), pesagem diária, monitorar edema/crepitações, restrição sódio, O2 se SpO2<95%',
                'noc':'Efetividade bomba cardíaca (0400); Equilíbrio hídrico (0601); Tolerância atividade (0005)'}
    if any(x in d for x in ['hipertensão','has','i10','crise hipertensiva','pressão alta']):
        return {'nanda1':'Risco de perfusão tissular cerebral ineficaz (NANDA 00201) — Domínio 4, Classe 4',
                'nanda2':'Dor aguda (NANDA 00132) — Domínio 12, Classe 1',
                'nanda3':'Deficiência de conhecimento (NANDA 00126) — Domínio 5, Classe 4',
                'plano':'monitorar PA ambos os membros, repouso ambiente calmo, anti-hipertensivos conforme prescrição, monitorar sinais neurológicos, restrição sódio, orientar adesão ao tratamento',
                'noc':'Estado neurológico (0909); Nível de dor (2102); Conhecimento: controle doença crônica (1847)'}
    if any(x in d for x in ['fibrilação atrial','fa ','i48','flutter']):
        return {'nanda1':'Débito cardíaco diminuído (NANDA 00029) — Domínio 4, Classe 4',
                'nanda2':'Risco de perfusão tissular ineficaz (NANDA 00204) — Domínio 4, Classe 4',
                'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
                'plano':'monitoração cardíaca contínua, controle FC e PA, anticoagulação conforme prescrição, cardioversão se indicada, monitorar sinais tromboembolismo, repouso relativo',
                'noc':'Estado cardíaco (0414); Perfusão tissular periférica (0407); Nível ansiedade (1211)'}
    # NEUROLÓGICO
    if any(x in d for x in ['avc','acidente vascular','i63','i64','i61','derrame']):
        return {'nanda1':'Perfusão tissular cerebral ineficaz (NANDA 00201) — Domínio 4, Classe 4',
                'nanda2':'Risco de aspiração (NANDA 00039) — Domínio 11, Classe 2',
                'nanda3':'Mobilidade física prejudicada (NANDA 00085) — Domínio 4, Classe 2',
                'plano':'cabeceira 30°, Glasgow 2/2h, avaliação pupilas/força/fala, posicionamento anti-contraturas, fisioterapia motora precoce, teste deglutição antes dieta oral, profilaxia TVP',
                'noc':'Perfusão tissular cerebral (0406); Estado neurológico (0909); Mobilidade (0208)'}
    if any(x in d for x in ['tce','traumatismo crânio','s06','trauma cranioence']):
        return {'nanda1':'Capacidade de recuperação intracraniana diminuída (NANDA 00049) — Domínio 11, Classe 2',
                'nanda2':'Risco de perfusão tissular cerebral ineficaz (NANDA 00201) — Domínio 4, Classe 4',
                'nanda3':'Risco de aspiração (NANDA 00039) — Domínio 11, Classe 2',
                'plano':'cabeceira 30°, Glasgow 1/1h, pupilas fotorreativas, PA rigorosa (evitar hipotensão), sinais herniação cerebral, restrição hídrica se prescrito, ambiente calmo estímulos mínimos',
                'noc':'Estado neurológico: consciência (0912); Perfusão tissular cerebral (0406); Estado respiratório (0403)'}
    if any(x in d for x in ['epilepsia','convuls','g40','g41','status epilept']):
        return {'nanda1':'Risco de lesão (NANDA 00035) — Domínio 11, Classe 2',
                'nanda2':'Risco de aspiração (NANDA 00039) — Domínio 11, Classe 2',
                'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
                'plano':'proteção lateral durante crise, não conter movimentos, decúbito lateral após crise, O2 disponível, monitorar pós-ictal, anticonvulsivante conforme prescrição, grades elevadas',
                'noc':'Controle do risco (1902); Estado respiratório (0403); Nível ansiedade (1211)'}
    # METABÓLICO / ENDÓCRINO
    if any(x in d for x in ['diabetes','dm ','e11','e10','glicemia','hiperglicemia','hipoglicemia','cetoacidose']):
        return {'nanda1':'Nível de glicemia instável (NANDA 00179) — Domínio 2, Classe 4',
                'nanda2':'Risco de infecção (NANDA 00004) — Domínio 11, Classe 1',
                'nanda3':'Deficiência de conhecimento (NANDA 00126) — Domínio 5, Classe 4',
                'plano':'glicemia capilar 6/6h, insulina conforme protocolo, sinais hipo/hiperglicemia, inspeção extremidades diária, cuidados com feridas, orientar dieta adequada',
                'noc':'Nível de glicemia (2300); Controle risco infeccioso (1924); Conhecimento: controle DM (1820)'}
    if any(x in d for x in ['sepse','a41','choque séptico','r57','séptico']):
        return {'nanda1':'Perfusão tissular ineficaz periférica (NANDA 00204) — Domínio 4, Classe 4',
                'nanda2':'Hipertermia (NANDA 00007) — Domínio 11, Classe 6',
                'nanda3':'Risco de choque (NANDA 00205) — Domínio 11, Classe 2',
                'plano':'SVs 1/1h, diurese rigorosa meta>0.5ml/kg/h, culturas antes ATB, ATB dentro do prazo (bundle sepse), acesso calibroso, reposição volemia, lactato seriado, nível consciência',
                'noc':'Perfusão tissular periférica (0407); Termorregulação (0800); Estado circulatório (0401)'}
    # RENAL
    if any(x in d for x in ['insuficiência renal','n17','n18','ira ','irc ','renal aguda','renal crônica','diálise']):
        return {'nanda1':'Eliminação urinária prejudicada (NANDA 00016) — Domínio 3, Classe 1',
                'nanda2':'Excesso de volume de líquidos (NANDA 00026) — Domínio 2, Classe 5',
                'nanda3':'Risco de desequilíbrio eletrolítico (NANDA 00195) — Domínio 2, Classe 5',
                'plano':'diurese horária rigorosa, balanço hídrico, restrição hídrica e potássio conforme prescrição, pesagem diária, eletrólitos, sinais hipercalemia (arritmias), cuidados acesso diálise se presente',
                'noc':'Eliminação urinária (0503); Equilíbrio hídrico (0601); Equilíbrio eletrolítico (0606)'}
    # GASTROINTESTINAL
    if any(x in d for x in ['pancreatite','k85']):
        return {'nanda1':'Dor aguda (NANDA 00132) — Domínio 12, Classe 1',
                'nanda2':'Nutrição desequilibrada: menor que as necessidades (NANDA 00002) — Domínio 2, Classe 1',
                'nanda3':'Risco de infecção (NANDA 00004) — Domínio 11, Classe 1',
                'plano':'jejum conforme prescrição, controle da dor (EVA), reposição volêmica, monitorar amilase/lipase, posição confortável (joelhos fletidos), eletrólitos, nutrição enteral se indicada',
                'noc':'Nível de dor (2102); Estado nutricional (1004); Controle infecção (1924)'}
    if any(x in d for x in ['hemorragia digestiva','k92','melena','hematêmese']):
        return {'nanda1':'Perfusão tissular ineficaz periférica (NANDA 00204) — Domínio 4, Classe 4',
                'nanda2':'Risco de choque (NANDA 00205) — Domínio 11, Classe 2',
                'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
                'plano':'acesso venoso calibroso, reposição volêmica rigorosa, monitorar PA/FC, jejum absoluto, preparar para endoscopia, monitorar hematócrito/hemoglobina seriados, decúbito dorsal',
                'noc':'Estado circulatório (0401); Controle risco (1902); Nível ansiedade (1211)'}
    # DEFAULT
    return {'nanda1':'Dor aguda (NANDA 00132) — Domínio 12, Classe 1',
            'nanda2':'Risco de infecção (NANDA 00004) — Domínio 11, Classe 1',
            'nanda3':'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
            'plano':'monitorar sinais vitais frequentemente, administrar medicamentos conforme prescrição, observar evolução clínica, manter conforto e segurança',
            'noc':'Nível de dor (2102); Controle do risco (1902); Nível de ansiedade (1211)'}

def _gerar_ia(tipo, p):
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key: return None

    sedado = any(x in p.get('queixas','').upper() for x in ['SEDADO','SEDADA','IOT','INTUBADO','INTUBADA','VM ','INCONSCIENTE'])
    ctx = "ATENÇÃO: Paciente sedado/intubado. Não use diagnósticos com relato verbal. Use dados objetivos." if sedado else ""

    diag_medico   = p.get('diagnostico', '')
    cid_codigo    = p.get('cid_codigo', '')
    diag_completo = f"{diag_medico}{' ('+cid_codigo+')' if cid_codigo else ''}".strip()
    dispositivos  = p.get('dispositivos', '')
    pendencias    = p.get('pendencias', '')

    # Mapeamento clínico — garante NANDA e plano específicos por patologia
    nc = _mapear_nanda_por_patologia(diag_completo)

    prompts = {
        'evolucao': f"""Você é enfermeiro(a) especialista em SAE. Gere EVOLUÇÃO SOAP para o paciente abaixo.
{ctx}
PACIENTE: {p.get('nome')} | LEITO: {p.get('leito')}
DIAGNÓSTICO MÉDICO: {diag_completo}
SINAIS VITAIS: {p.get('sv')}
QUEIXAS/ESTADO GERAL: {p.get('queixas')}
SISTEMAS AVALIADOS: {', '.join(p.get('sistemas',[]))}
DISPOSITIVOS: {dispositivos or p.get('exames','')}
ALERGIAS: {p.get('alergias','')}
OBS: {p.get('obs','')}

OS 3 DIAGNÓSTICOS NANDA JÁ FORAM DEFINIDOS — USE EXATAMENTE ESTES:
1º DIAGNÓSTICO (PRIORITÁRIO): {nc['nanda1']}
2º DIAGNÓSTICO: {nc['nanda2']}
3º DIAGNÓSTICO: {nc['nanda3']}

INTERVENÇÕES BASE PARA {diag_completo}: {nc['plano']}
NOC: {nc['noc']}

ESTRUTURA OBRIGATÓRIA:
EVOLUÇÃO DE ENFERMAGEM
Data: ___/___/______ Hora: ____:____ Turno: ( )Manhã ( )Tarde ( )Noite

S — SUBJETIVO: [queixas reais do paciente usando dados acima]
O — OBJETIVO: [SVs reais: {p.get('sv')} | achados físicos | dispositivos: {dispositivos or p.get('exames','')}]
A — AVALIAÇÃO:
1. {nc['nanda1']} | Relacionado a: [fator específico de {diag_completo}] | Evidenciado por: [dados reais]
2. {nc['nanda2']} | Relacionado a: [...] | Evidenciado por: [...]
3. {nc['nanda3']} | Relacionado a: [...] | Evidenciado por: [...]
P — PLANO NIC ESPECÍFICO PARA {diag_completo.upper()}:
[Expanda: {nc['plano']} com horários e detalhes clínicos do paciente — mínimo 8 intervenções]
NOC: {nc['noc']}

Enfermeiro(a): _________________________ COREN: _________""",

        'prescricao': f"""Você é enfermeiro(a) especialista. Gere PRESCRIÇÃO DE ENFERMAGEM individualizada para o diagnóstico informado.
{ctx}
PACIENTE: {p.get('nome')} | LEITO: {p.get('leito')}
DIAGNÓSTICO MÉDICO: {diag_completo}
DIAGNÓSTICO DE ENFERMAGEM (NANDA): {nc['nanda1']}
SINAIS VITAIS: {p.get('sv')}
QUEIXAS: {p.get('queixas')}
DISPOSITIVOS: {dispositivos or p.get('exames','')}
ALERGIAS: {p.get('alergias','')}
PENDÊNCIAS DO TURNO: {pendencias}

PRESCRIÇÃO DE ENFERMAGEM
Data: ___/___/______ Turno: ( )Manhã ( )Tarde ( )Noite
Paciente: {p.get('nome')} | Leito: {p.get('leito')}
Diagnóstico Médico: {diag_completo}

DIAGNÓSTICOS DE ENFERMAGEM (NANDA-I 2024-2026):
1. {nc['nanda1']}
   Relacionado a: [fator específico de {diag_completo}]
   Evidenciado por: [dados clínicos reais: {p.get('queixas')}]
2. {nc['nanda2']}
   Relacionado a: [...] | Evidenciado por: [...]

PRESCRIÇÃO — CUIDADOS ESPECÍFICOS PARA {diag_completo.upper()}:
[Baseado em: {nc['plano']} — expanda em MÍNIMO 14 itens numerados com horários específicos, usando dados reais do paciente]

RESULTADOS ESPERADOS (NOC): {nc['noc']}

Enfermeiro(a): _________________________ COREN: _________""",

        'passagem': f"""Você é enfermeiro(a) especialista. Gere PASSAGEM DE PLANTÃO com os modelos SBAR e FAST HUG.
{ctx}
PACIENTE: {p.get('nome')} | LEITO: {p.get('leito')}
DIAGNÓSTICO MÉDICO: {diag_completo}
SINAIS VITAIS: {p.get('sv')}
SITUAÇÃO ATUAL: {p.get('queixas')}
DISPOSITIVOS: {dispositivos or p.get('exames','')}
ALERGIAS: {p.get('alergias','')}
PENDÊNCIAS DO TURNO: {pendencias}

PASSAGEM DE PLANTÃO
Data: ___/___/______ | De: _______________ Para: _______________

━━━ MODELO SBAR ━━━
S — SITUAÇÃO: [identificação, diagnóstico médico real, motivo internação]
B — BACKGROUND: [comorbidades, alergias, dispositivos, exames relevantes, evolução]
A — AVALIAÇÃO: [SVs reais: {p.get('sv')}, NANDA prioritário: {nc['nanda1']}, achados relevantes]
R — RECOMENDAÇÕES: [alertas específicos para {diag_completo}, pendências, cuidados prioritários próximo turno: {pendencias}]

━━━ FAST HUG (checklist de cuidados intensivos) ━━━
F — Feeding (alimentação/nutrição): [status e via de alimentação]
A — Analgesia: [controle da dor, escala utilizada, medicamento]
S — Sedação: [nível de sedação se aplicável, escala]
T — Thrombus (profilaxia TVP): [anticoagulante, meias compressivas]
H — HOB (cabeceira elevada): [grau de elevação]
U — Úlcera (profilaxia gástrica): [protetor gástrico conforme prescrição]
G — Glicemia: [valor atual, meta glicêmica, insulinoterapia]

Enfermeiro(a): _________________________ COREN: _________""",

        'nanda': f"""Você é especialista em NANDA-I 2024-2026. Gere 4 diagnósticos de enfermagem para o paciente.
{ctx}
PACIENTE: {p.get('nome')} | LEITO: {p.get('leito')}
DIAGNÓSTICO MÉDICO: {diag_completo}
SINAIS VITAIS: {p.get('sv')}
AVALIAÇÃO: {p.get('queixas')}
DISPOSITIVOS: {dispositivos or p.get('exames','')}

OS 3 PRIMEIROS DIAGNÓSTICOS JÁ FORAM DEFINIDOS — USE EXATAMENTE ESTES:
1º (ALTA PRIORIDADE): {nc['nanda1']}
2º (MÉDIA PRIORIDADE): {nc['nanda2']}
3º (MÉDIA PRIORIDADE): {nc['nanda3']}
4º diagnóstico: defina com base nos dados do paciente acima

DIAGNÓSTICOS DE ENFERMAGEM — NANDA-I 2024-2026
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico Médico: {diag_completo}

[Para cada diagnóstico:]
DIAGNÓSTICO X — PRIORIDADE: [ALTA/MÉDIA/BAIXA]
Nome: [exatamente conforme definido acima]
Domínio/Classe: [conforme NANDA-I]
Relacionado a: [fator específico de {diag_completo} usando dados reais]
Evidenciado por: [dados reais: {p.get('queixas')} / {p.get('sv')}]
Intervenções NIC (mín 5): [baseado em: {nc['plano']}]
Resultados NOC: {nc['noc']}

Enfermeiro(a): _________________________ COREN: _________"""
    }

    try:
        r = requests.post('https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': 'claude-sonnet-4-6', 'max_tokens': 4000,
                  'messages': [{'role': 'user', 'content': prompts.get(tipo, prompts['evolucao'])}]}, timeout=45)
        return r.json()['content'][0]['text']
    except Exception as e:
        print(f'Erro IA: {e}')
        return None



# ────────────────────────────────────────────────────────────
# ESCALA DE FUGULIN — classificação do grau de dependência
# ────────────────────────────────────────────────────────────
FUGULIN_ITENS = {
    'estado_mental': {'nome': 'Estado Mental', 'opcoes': [
        {'valor': 1, 'desc': 'Orientado'},
        {'valor': 2, 'desc': 'Desorientado / agitado'},
        {'valor': 3, 'desc': 'Comatoso / inconsciente'},
    ]},
    'oxigenacao': {'nome': 'Oxigenação', 'opcoes': [
        {'valor': 1, 'desc': 'Sem suporte'},
        {'valor': 2, 'desc': 'O2 máscara / cateter'},
        {'valor': 3, 'desc': 'IOT / VM'},
    ]},
    'sinais_vitais': {'nome': 'Sinais Vitais', 'opcoes': [
        {'valor': 1, 'desc': 'Estáveis, verificação 2/2h'},
        {'valor': 2, 'desc': 'Instáveis, verificação 1/1h'},
        {'valor': 3, 'desc': 'Monitoração contínua'},
    ]},
    'nutricao': {'nome': 'Nutrição / Hidratação', 'opcoes': [
        {'valor': 1, 'desc': 'Via oral sem auxílio'},
        {'valor': 2, 'desc': 'Via oral com auxílio'},
        {'valor': 3, 'desc': 'Sonda / parenteral'},
    ]},
    'motilidade': {'nome': 'Motilidade', 'opcoes': [
        {'valor': 1, 'desc': 'Deambula sem auxílio'},
        {'valor': 2, 'desc': 'Deambula com auxílio'},
        {'valor': 3, 'desc': 'Restrito ao leito'},
    ]},
    'deambulacao': {'nome': 'Deambulação', 'opcoes': [
        {'valor': 1, 'desc': 'Sem restrições'},
        {'valor': 2, 'desc': 'Com restrições'},
        {'valor': 3, 'desc': 'Imobilizado'},
    ]},
    'cuidado_corporal': {'nome': 'Cuidado Corporal', 'opcoes': [
        {'valor': 1, 'desc': 'Independente'},
        {'valor': 2, 'desc': 'Auxílio parcial'},
        {'valor': 3, 'desc': 'Dependência total'},
    ]},
    'eliminacoes': {'nome': 'Eliminações', 'opcoes': [
        {'valor': 1, 'desc': 'Controle dos esfíncteres'},
        {'valor': 2, 'desc': 'Incontinência ocasional'},
        {'valor': 3, 'desc': 'SVD / incontinência total'},
    ]},
    'terapeutica': {'nome': 'Terapêutica', 'opcoes': [
        {'valor': 1, 'desc': 'Medicamentos VO / curativo simples'},
        {'valor': 2, 'desc': 'Medicamentos EV / curativo complexo'},
        {'valor': 3, 'desc': 'Drogas vasoativas / cuidados intensivos'},
    ]},
}

@app.route('/api/escores/fugulin-itens', methods=['GET'])
@jwt_required()
def fugulin_itens():
    """Retorna itens da Escala de Fugulin para o frontend"""
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    return jsonify(FUGULIN_ITENS)

@app.route('/api/escores/fugulin-calcular', methods=['POST'])
@jwt_required()
def fugulin_calcular():
    """Calcula Escala de Fugulin e retorna classificação"""
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    data = request.json
    scores = data.get('scores', {})
    total = sum(int(v) for v in scores.values() if str(v).isdigit())
    if total <= 9:
        classificacao = 'Mínimo — Cuidados mínimos (PCM)'
        cor = 'verde'
    elif total <= 12:
        classificacao = 'Intermediário — Cuidados intermediários (PCI)'
        cor = 'amarelo'
    elif total <= 18:
        classificacao = 'Semi-intensivo — Cuidados semi-intensivos (PCSI)'
        cor = 'laranja'
    else:
        classificacao = 'Intensivo — Cuidados intensivos (PCI intensivo)'
        cor = 'vermelho'
    return jsonify({'total': total, 'classificacao': classificacao, 'cor': cor,
                    'itens_max': 27, 'percentual': round(total/27*100)})


# ────────────────────────────────────────────────────────────
# DISPOSITIVOS — seleção rápida + histórico por paciente
# ────────────────────────────────────────────────────────────
DISPOSITIVOS_PADRAO = [
    'AVP — Acesso Venoso Periférico',
    'CICC — Cateter Venoso Central Inserção Cirúrgica',
    'FICC — Cateter Venoso Central Femoral',
    'Portocath — Cateter Totalmente Implantável',
    'PICC — Cateter Central de Inserção Periférica',
    'Sonda Vesical de Demora (SVD)',
    'Sonda Enteral Nasal','Sonda Enteral Oral',
    'Sonda Gástrica Nasal','Sonda Gástrica Oral',
    'Tubo Orotraqueal (TOT)','Traqueostomia',
    'Cateter de Diálise','Fístula Arteriovenosa',
    'Bolsa de Colostomia','Bolsa de Ileostomia',
]

@app.route('/api/dispositivos/lista-padrao', methods=['GET'])
@jwt_required()
def lista_dispositivos_padrao():
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    return jsonify(DISPOSITIVOS_PADRAO)

@app.route('/api/dispositivos', methods=['GET'])
@jwt_required()
def listar_dispositivos():
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    leito = request.args.get('leito','')
    q = Dispositivo.query.filter_by(usuario_id=uid, ativo=True)
    if leito: q = q.filter_by(leito=leito)
    devs = q.order_by(Dispositivo.criado_em.desc()).all()
    return jsonify([{'id':d.id,'paciente':d.paciente,'leito':d.leito,'nome':d.nome,
        'data_insercao':d.data_insercao,'observacao':d.observacao,
        'criado_em':d.criado_em.isoformat()} for d in devs])

@app.route('/api/dispositivos', methods=['POST'])
@jwt_required()
def adicionar_dispositivo():
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    data = request.json
    if not data.get('nome'): return jsonify({'erro':'Nome obrigatorio'}),400
    d = Dispositivo(usuario_id=uid,paciente=data.get('paciente',''),
        leito=data.get('leito',''),nome=data['nome'],
        data_insercao=data.get('data_insercao',''),observacao=data.get('observacao',''))
    db.session.add(d)
    db.session.commit()
    return jsonify({'ok':True,'id':d.id}),201

@app.route('/api/dispositivos/<int:did>', methods=['DELETE'])
@jwt_required()
def remover_dispositivo(did):
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    d = Dispositivo.query.filter_by(id=did,usuario_id=uid).first()
    if not d: return jsonify({'erro':'Nao encontrado'}),404
    d.ativo = False
    db.session.commit()
    return jsonify({'ok':True})

# ────────────────────────────────────────────────────────────
# PENDÊNCIAS — inclusão manual pelo profissional
# ────────────────────────────────────────────────────────────
@app.route('/api/pendencias', methods=['GET'])
@jwt_required()
def listar_pendencias():
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    leito = request.args.get('leito','')
    q = Pendencia.query.filter_by(usuario_id=uid,resolvida=False)
    if leito: q = q.filter_by(leito=leito)
    pends = q.order_by(Pendencia.criado_em.desc()).all()
    return jsonify([{'id':p.id,'paciente':p.paciente,'leito':p.leito,
        'descricao':p.descricao,'resolvida':p.resolvida,
        'criado_em':p.criado_em.isoformat()} for p in pends])

@app.route('/api/pendencias', methods=['POST'])
@jwt_required()
def adicionar_pendencia():
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    data = request.json
    if not data.get('descricao'): return jsonify({'erro':'Descricao obrigatoria'}),400
    p = Pendencia(usuario_id=uid,paciente=data.get('paciente',''),
        leito=data.get('leito',''),descricao=data['descricao'])
    db.session.add(p)
    db.session.commit()
    return jsonify({'ok':True,'id':p.id}),201

@app.route('/api/pendencias/<int:pid>/resolver', methods=['POST'])
@jwt_required()
def resolver_pendencia(pid):
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    p = Pendencia.query.filter_by(id=pid,usuario_id=uid).first()
    if not p: return jsonify({'erro':'Nao encontrada'}),404
    p.resolvida = True
    db.session.commit()
    return jsonify({'ok':True})

@app.route('/api/pendencias/<int:pid>', methods=['DELETE'])
@jwt_required()
def excluir_pendencia(pid):
    if not validar_sessao(): return jsonify({'erro':'Sessao invalida.','sessao_invalida':True}),401
    uid = int(get_jwt_identity())
    p = Pendencia.query.filter_by(id=pid,usuario_id=uid).first()
    if not p: return jsonify({'erro':'Nao encontrada'}),404
    db.session.delete(p)
    db.session.commit()
    return jsonify({'ok':True})

# ROTAS ESTATICAS
@app.route('/favicon.ico')
def favicon(): return ('', 204)

@app.route('/')
def index(): return send_from_directory(app.static_folder, 'index.html')

@app.route('/admin.html')
def admin_html(): return send_from_directory(app.static_folder, 'admin.html')

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api'):
        return jsonify({'erro': 'Rota nao encontrada'}), 404
    return send_from_directory(app.static_folder, 'index.html')

# INIT
with app.app_context():
    db.create_all()
    migrar_banco()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
