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

# ────────────────────────────────────────────────────────────
# SECURITY HEADERS — aplicados em todas as respostas
# ────────────────────────────────────────────────────────────
@app.after_request
def aplicar_security_headers(response):
    # Previne clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Previne MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS protection (legacy browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # HSTS — força HTTPS por 1 ano (só ativa em produção)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CSP — permite apenas recursos do próprio domínio + CDNs confiáveis
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://api.anthropic.com; "
        "frame-ancestors 'none';"
    )
    return response

# ────────────────────────────────────────────────────────────
# SANITIZAÇÃO DE INPUT — remove caracteres perigosos
# ────────────────────────────────────────────────────────────
import re as _re

def sanitizar(texto, max_len=500):
    """Remove tags HTML/script e limita tamanho do input"""
    if not texto or not isinstance(texto, str):
        return ''
    # Remove tags HTML
    texto = _re.sub(r'<[^>]+>', '', texto)
    # Remove scripts inline
    texto = _re.sub(r'(?i)(javascript:|vbscript:|onload=|onerror=|onclick=)', '', texto)
    # Limita tamanho
    return texto[:max_len].strip()

def sanitizar_pac(pac):
    """Sanitiza todos os campos do paciente antes de processar"""
    campos_curtos = ['nome','leito','diagnostico','cid_codigo','alergias','obs']
    campos_longos = ['sv','queixas','exames','dispositivos','pendencias']
    for campo in campos_curtos:
        if campo in pac:
            pac[campo] = sanitizar(pac[campo], 200)
    for campo in campos_longos:
        if campo in pac:
            pac[campo] = sanitizar(pac[campo], 1000)
    return pac


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


# ────────────────────────────────────────────────────────────
# RATE LIMITING SIMPLES — sem dependência externa
# Limita tentativas por IP em endpoints críticos
# ────────────────────────────────────────────────────────────
from collections import defaultdict
import time as _time

_rate_store = defaultdict(list)  # {ip: [timestamps]}

def check_rate_limit(ip, max_req=10, janela=60):
    """Retorna True se dentro do limite, False se excedeu"""
    agora = _time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if agora - t < janela]
    if len(_rate_store[ip]) >= max_req:
        return False
    _rate_store[ip].append(agora)
    return True

def rate_limit_response():
    return jsonify({
        'erro': 'Muitas requisições. Aguarde alguns minutos antes de tentar novamente.',
        'rate_limited': True
    }), 429

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


# ────────────────────────────────────────────────────────────
# LOG DE SEGURANÇA — alertas e auditoria
# ────────────────────────────────────────────────────────────
def log_seguranca(evento, email='', ip='', detalhe='', nivel='INFO'):
    """Log estruturado de eventos de segurança"""
    import json as _json
    entrada = {
        'timestamp': datetime.utcnow().isoformat(),
        'nivel': nivel,
        'evento': evento,
        'email': email,
        'ip': ip,
        'detalhe': detalhe[:500] if detalhe else ''
    }
    print(f'[SEGURANCA] {_json.dumps(entrada, ensure_ascii=False)}')
    # Alertas críticos
    if nivel == 'CRITICO':
        print(f'[ALERTA CRITICO] {evento} | Email: {email} | IP: {ip} | {detalhe}')

def log_tentativa_suspeita(email, ip, motivo):
    """Registra e alerta sobre tentativas suspeitas"""
    log_seguranca('TENTATIVA_SUSPEITA', email=email, ip=ip, detalhe=motivo, nivel='AVISO')
    # Verificar se o IP tentou muitas contas diferentes (credential stuffing)
    try:
        tentativas_ip = LogAcesso.query.filter_by(
            ip=ip, sucesso=False
        ).filter(
            LogAcesso.criado_em >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        if tentativas_ip >= 20:
            log_seguranca('POSSIVEL_ATAQUE_FORCA_BRUTA', ip=ip,
                detalhe=f'{tentativas_ip} falhas na ultima hora', nivel='CRITICO')
    except: pass

# AUTENTICAÇÃO
@app.route('/api/auth/registro', methods=['POST'])
def registro():
    # Rate limiting: max 5 registros por IP por hora
    ip = get_ip()
    if not check_rate_limit(ip, max_req=5, janela=3600):
        return rate_limit_response()
    data = request.json or {}
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
    # Rate limiting: max 10 tentativas de login por IP por minuto
    ip = get_ip()
    if not check_rate_limit(ip, max_req=10, janela=60):
        return rate_limit_response()
    data = request.json or {}
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
            log_tentativa_suspeita(u.email, ip, f'Conta bloqueada apos 5 tentativas')
            return jsonify({'erro': 'Muitas tentativas. Bloqueado por 15 minutos.'}), 403
        db.session.commit()
        registrar_acesso(u.id, u.email, False)
        log_tentativa_suspeita(u.email, ip, f'Senha incorreta tentativa {u.tentativas_login}')
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
        return jsonify({'erro': 'Seu período gratuito expirou. Assine o Plano Pro por R$ 97,00/mês para continuar.', 'limite': True, 'expirado': True}), 403
    # Rate limiting: max 30 SAEs por minuto por usuário
    ip = get_ip()
    uid_str = get_jwt_identity()
    if not check_rate_limit(f'sae_{uid_str}', max_req=30, janela=60):
        return rate_limit_response()
    data = request.json or {}
    tipo = data.get('tipo', 'evolucao')
    pac = sanitizar_pac(data.get('paciente', {}))
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
    # Rate limiting: max 3 recuperações por IP por hora
    ip = get_ip()
    if not check_rate_limit(f'recup_{ip}', max_req=3, janela=3600):
        return rate_limit_response()
    import secrets, string
    data = request.json or {}
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
    # Rate limiting básico no webhook
    ip = get_ip()
    if not check_rate_limit(f'webhook_{ip}', max_req=20, janela=60):
        return rate_limit_response()
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


@app.route('/api/admin/seguranca/<secret>')
def admin_seguranca(secret):
    """Painel de segurança — IPs suspeitos e tentativas recentes"""
    if not check_admin(secret): return 'Sem permissao', 403
    from collections import Counter
    ultima_hora = datetime.utcnow() - timedelta(hours=1)
    ultimas_24h = datetime.utcnow() - timedelta(hours=24)
    # Falhas recentes
    falhas_1h = LogAcesso.query.filter(
        LogAcesso.sucesso==False,
        LogAcesso.criado_em>=ultima_hora
    ).all()
    # IPs com mais falhas
    ips_suspeitos = Counter(l.ip for l in falhas_1h).most_common(10)
    # Total últimas 24h
    total_24h = LogAcesso.query.filter(LogAcesso.criado_em>=ultimas_24h).count()
    falhas_24h = LogAcesso.query.filter(
        LogAcesso.sucesso==False, LogAcesso.criado_em>=ultimas_24h
    ).count()
    return jsonify({
        'falhas_ultima_hora': len(falhas_1h),
        'falhas_24h': falhas_24h,
        'total_acessos_24h': total_24h,
        'ips_suspeitos': [{'ip': ip, 'tentativas': n} for ip, n in ips_suspeitos],
        'usuarios_bloqueados': Usuario.query.filter_by(bloqueado=True).count(),
        'status': 'ok'
    })

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

# ────────────────────────────────────────────────────────────
# BANCO DE PRESCRIÇÕES DE ENFERMAGEM POR CID-10
# Cada patologia tem itens clínicos específicos e individualizados
# Usado para enriquecer o prompt da IA com cuidados reais
# ────────────────────────────────────────────────────────────
PRESCRICOES_POR_CID = {

    # ── DENGUE ──────────────────────────────────────────────
    'dengue_classica': {
        'cids': ['a90','dengue clássica','dengue classica','febre dengue'],
        'classificacao': 'Dengue sem sinais de alarme (Tipo A/B)',
        'itens': [
            '1. Monitorar sinais vitais (PA, FC, FR, T°, SpO2) a cada 4 horas ou conforme prescrição',
            '2. Avaliar e registrar nível de consciência e estado geral',
            '3. Monitorar temperatura corporal e administrar antitérmico conforme prescrição (PARACETAMOL — NUNCA AAS ou ibuprofeno)',
            '4. Incentivar hidratação oral: oferecer 60ml/kg/dia se tolerado (água, soro caseiro, sucos sem corante)',
            '5. Avaliar aceitação da dieta e hidratação oral a cada refeição',
            '6. Monitorar sinais de sangramento: petéquias, equimoses, epistaxe, gengivorragia, hematêmese, melena',
            '7. Realizar e registrar balanço hídrico rigoroso (ingesta e diurese)',
            '8. Monitorar diurese: volume, frequência e características',
            '9. Avaliar dor com escala visual analógica (EVA) e administrar analgésico conforme prescrição',
            '10. Observar e registrar náuseas, vômitos e sintomas gastrointestinais',
            '11. Verificar resultado de plaquetas e hematócrito conforme solicitação médica',
            '12. Orientar o paciente e família sobre sinais de alarme: dor abdominal intensa, vômitos persistentes, sangramento, sonolência excessiva',
            '13. Manter repouso relativo no leito durante o período febril',
            '14. Registrar evolução de enfermagem com dados objetivos a cada turno',
            '15. Comunicar ao médico qualquer alteração clínica imediatamente',
        ],
        'alertas': 'ATENÇÃO: Vigiar sinais de alarme — dor abdominal intensa, vômitos persistentes, acúmulo de líquidos, sangramento, letargia, aumento do hematócrito com queda rápida de plaquetas',
    },

    'dengue_alarme': {
        'cids': ['a97.1','dengue sinais de alarme','dengue tipo b','dengue com sinais'],
        'classificacao': 'Dengue com sinais de alarme (Tipo C)',
        'itens': [
            '1. Monitorar sinais vitais (PA, FC, FR, T°, SpO2) a cada 1 hora — atenção para hipotensão e taquicardia',
            '2. Avaliar perfusão periférica: TEC, temperatura das extremidades, pulso periférico a cada hora',
            '3. Manter acesso venoso periférico (AVP) calibroso pérvio — verificar e registrar a cada turno',
            '4. Administrar hidratação venosa endovenosa conforme prescrição médica: soluções cristaloides (SF 0,9% ou Ringer Lactato)',
            '5. Realizar e registrar balanço hídrico rigoroso HORÁRIO (ingesta EV + oral x diurese)',
            '6. Monitorar diurese HORÁRIA — meta mínima 0,5ml/kg/hora — comunicar oligúria imediatamente',
            '7. Monitorar ativamente sinais de choque: hipotensão, taquicardia, enchimento capilar lentificado, alteração de consciência',
            '8. Monitorar sinais de sangramento: petéquias, equimoses, sangramento em locais de punção, hematêmese, melena, hematúria',
            '9. Monitorar nível de consciência (Escala de Glasgow) a cada hora',
            '10. Verificar resultados laboratoriais: plaquetas, hematócrito, hemoglobina, coagulograma — registrar e comunicar alterações',
            '11. Administrar antitérmico conforme prescrição (PARACETAMOL — NUNCA AAS ou ibuprofeno)',
            '12. Avaliar e controlar dor com EVA — administrar analgésico conforme prescrição',
            '13. Monitorar sinais de extravasamento plasmático: edema, derrame pleural, ascite',
            '14. Observar e registrar manifestações hemorrágicas espontâneas ou em locais de punção',
            '15. Manter repouso absoluto no leito',
            '16. Comunicar IMEDIATAMENTE ao médico: deterioração clínica, queda de PA, oligúria, sinais de sangramento ativo',
            '17. Registrar evolução de enfermagem detalhada a cada turno com todos os parâmetros',
            '18. Preparar material para expansão volêmica de emergência',
        ],
        'alertas': 'CRITICAMENTE IMPORTANTE: Dengue com sinais de alarme requer monitoramento intensivo. Vigilância contínua para choque e sangramento. Comunicar médico imediatamente ante qualquer deterioração.',
    },

    'dengue_grave': {
        'cids': ['a91','a97.2','dengue hemorrágica','dengue grave','dengue tipo d','dengue tipo c'],
        'classificacao': 'Dengue grave / Dengue hemorrágica (Tipo D)',
        'itens': [
            '1. Monitorar sinais vitais CONTÍNUOS ou a cada 30 minutos — manter PA sistólica >90mmHg',
            '2. Avaliar perfusão periférica a cada 30 minutos: TEC, temperatura extremidades, cianose',
            '3. Manter 2 acessos venosos calibrosos ou acesso venoso central conforme prescrição',
            '4. Administrar expansão volêmica agressiva conforme prescrição (cristaloide 20ml/kg em 15-30min se choque)',
            '5. Monitorar diurese HORÁRIA rigorosa — meta >0,5ml/kg/h — instalar SVD se necessário',
            '6. Realizar balanço hídrico HORÁRIO rigoroso',
            '7. Monitorar nível de consciência com Escala de Glasgow a cada 30 minutos',
            '8. Vigilância intensa para sangramento ativo: mucosas, locais de punção, abdome, SNC',
            '9. Contraindicado: AAS, AINEs, injeções intramusculares, anticoagulantes',
            '10. Administrar hemoderivados conforme prescrição médica (plaquetas, plasma)',
            '11. Monitorar sinais de SARA: SpO2, FR, padrão respiratório — O2 suplementar conforme prescrição',
            '12. Avaliar abdome: dor, distensão, hepatomegalia dolorosa a cada turno',
            '13. Monitorar exames laboratoriais seriados: HT, Hb, plaquetas, coagulograma, lactato, gasometria',
            '14. Manter repouso absoluto — elevar cabeceira 30° se dispneia',
            '15. Comunicar IMEDIATAMENTE ao médico qualquer deterioração clínica',
            '16. Registrar evolução detalhada a cada turno — incluir todos os parâmetros hemodinâmicos',
            '17. Preparar material para IOT e suporte ventilatório se necessário',
            '18. Suporte emocional ao paciente e família — orientar sobre gravidade e conduta',
        ],
        'alertas': 'URGÊNCIA: Dengue grave/hemorrágica. Risco de vida. Monitoramento contínuo. UTI se instável.',
    },

    # ── RESPIRATÓRIO ────────────────────────────────────────
    'asma_crise': {
        'cids': ['j45','j46','asma','broncoespas','crise asmat'],
        'classificacao': 'Asma — Crise broncoespástica',
        'itens': [
            '1. Posicionar paciente em Fowler 45° ou posição de conforto para respirar',
            '2. Monitorar SpO2 contínua — meta >95% — iniciar O2 suplementar se SpO2 <92%',
            '3. Administrar broncodilatador inalatório (salbutamol) conforme prescrição — registrar resposta',
            '4. Monitorar FR, padrão respiratório e uso de musculatura acessória a cada 30 minutos',
            '5. Auscultar campos pulmonares antes e após broncodilatador — registrar achados',
            '6. Administrar corticoide EV/VO conforme prescrição médica',
            '7. Manter acesso venoso pérvio para medicação de emergência',
            '8. Avaliar e controlar fator desencadeante da crise',
            '9. Monitorar FC e PA — broncodilatador pode causar taquicardia',
            '10. Avaliar nível de ansiedade e oferecer suporte emocional — ansiedade piora broncoespasmo',
            '11. Preparar material para nebulização e IOT em caso de deterioração',
            '12. Orientar sobre técnica correta de uso do inalador após a crise',
            '13. Registrar evolução respiratória a cada turno com dados objetivos',
            '14. Comunicar médico imediatamente se piora ou não resposta à medicação',
        ],
        'alertas': 'Vigilância para status asmaticus. Preparar IOT se SpO2 <88% ou cansaço extremo.',
    },

    'dpoc_exac': {
        'cids': ['j44','dpoc','doença pulmonar obstrutiva'],
        'classificacao': 'DPOC com exacerbação',
        'itens': [
            '1. Posicionar em semi-Fowler 30-45° para otimizar ventilação',
            '2. Administrar O2 de forma CONTROLADA — meta SpO2 88-92% (risco de retenção de CO2)',
            '3. Monitorar SpO2, FR e padrão respiratório continuamente',
            '4. Atentar para sinais de hipercapnia: sonolência, confusão, cefaleia — comunicar médico',
            '5. Administrar broncodilatador nebulizado conforme prescrição',
            '6. Realizar fisioterapia respiratória: técnica de respiração com lábios franzidos, drenagem postural',
            '7. Incentivar tosse dirigida para eliminar secreções',
            '8. Auscultar campos pulmonares a cada turno — registrar sibilos, roncos, crepitações',
            '9. Monitorar gasometria arterial conforme solicitação médica',
            '10. Manter acesso venoso pérvio para corticoide e ATB EV se prescritos',
            '11. Monitorar sinais vitais a cada 2 horas',
            '12. Avaliar nível de consciência e orientação temporal/espacial a cada turno',
            '13. Orientar paciente sobre cessação do tabagismo',
            '14. Registrar evolução respiratória detalhada a cada turno',
        ],
        'alertas': 'ATENÇÃO: O2 controlado — hiperóxia pode suprimir drive respiratório hipóxico. Meta SpO2 88-92%.',
    },

    'pneumonia_tto': {
        'cids': ['j18','j15','j12','pneumonia'],
        'classificacao': 'Pneumonia — tratamento hospitalar',
        'itens': [
            '1. Elevar cabeceira 30-45° para facilitar expansão pulmonar e prevenir aspiração',
            '2. Monitorar SpO2 contínua — administrar O2 suplementar se SpO2 <94%',
            '3. Administrar antibioticoterapia EV rigorosamente no horário prescrito',
            '4. Monitorar temperatura a cada 4 horas — administrar antitérmico conforme prescrição',
            '5. Auscultar campos pulmonares a cada turno — registrar crepitações, broncofonias',
            '6. Realizar fisioterapia respiratória para mobilização de secreções',
            '7. Incentivar expectoração e hidratação oral adequada',
            '8. Monitorar exames laboratoriais: hemograma, PCR, culturas — registrar resultados',
            '9. Manter hidratação venosa conforme balanço hídrico e prescrição',
            '10. Avaliar dor pleurítica — administrar analgésico conforme prescrição',
            '11. Monitorar sinais vitais a cada 4 horas',
            '12. Coletar amostras para cultura conforme prescrição médica antes do ATB',
            '13. Avaliar evolução clínica: febre, dispneia, produção de escarro',
            '14. Registrar evolução de enfermagem a cada turno',
            '15. Comunicar médico se piora clínica ou não resposta ao ATB em 48-72h',
        ],
        'alertas': 'Atenção para sinais de deterioração: piora da SpO2, sepse, derrame pleural.',
    },

    # ── CARDIOVASCULAR ──────────────────────────────────────
    'iam_tto': {
        'cids': ['i21','i22','infarto','iam','supra de st'],
        'classificacao': 'IAM — fase aguda',
        'itens': [
            '1. Manter repouso absoluto no leito nas primeiras 12-24 horas',
            '2. Monitoração cardíaca contínua — ECG contínuo — registrar arritmias',
            '3. Manter 2 acessos venosos calibrosos pérvios',
            '4. Avaliar e controlar dor torácica com EVA — administrar analgésico conforme prescrição',
            '5. Administrar antiagregantes plaquetários e anticoagulantes conforme prescrição e horário',
            '6. Realizar ECG seriado conforme prescrição médica',
            '7. Coletar enzimas cardíacas (CK-MB, Troponina) conforme prescrição',
            '8. Monitorar PA e FC a cada 1 hora na fase aguda',
            '9. Administrar O2 se SpO2 <95% — avaliar necessidade contínua',
            '10. Monitorar sinais de complicações: arritmias, ICC, choque cardiogênico',
            '11. Manter paciente em NPO se indicado para cateterismo',
            '12. Avaliar perfusão periférica: TEC, temperatura de extremidades, diurese',
            '13. Controle rigoroso de diurese — atenção para oligúria (ICC)',
            '14. Oferecer suporte emocional — ambiente calmo e tranquilo',
            '15. Orientar paciente sobre importância do repouso e comunicar qualquer dor',
            '16. Registrar evolução cardíaca detalhada a cada turno',
        ],
        'alertas': 'Vigilância contínua para: arritmias graves, choque cardiogênico, extensão do infarto.',
    },

    'icc_descomp': {
        'cids': ['i50','insuficiência cardíaca','icc'],
        'classificacao': 'ICC descompensada',
        'itens': [
            '1. Posicionar em Fowler 45° ou ortopneia conforme tolerância',
            '2. Elevar MMII 30° para retorno venoso — exceto se hipotensão',
            '3. Monitorar PA, FC, FR e SpO2 a cada 2 horas',
            '4. Pesar paciente diariamente em jejum — registrar e comunicar ganho >1kg/dia',
            '5. Controle rigoroso de diurese HORÁRIA — meta conforme prescrição médica',
            '6. Realizar balanço hídrico rigoroso — registrar TODA ingesta e excreta',
            '7. Restringir ingesta hídrica conforme prescrição médica',
            '8. Administrar diurético EV rigorosamente no horário',
            '9. Monitorar eletrólitos séricos — atenção para hipocalemia com diuréticos',
            '10. Avaliar edema de MMII: grau, extensão, cacifo — registrar diariamente',
            '11. Auscultar campos pulmonares: crepitações basais, sibilos',
            '12. Restringir sódio na dieta — orientar paciente e família',
            '13. Monitorar sinais de hipoperfusão: alteração de consciência, oligúria, cianose',
            '14. Administrar O2 se SpO2 <94%',
            '15. Registrar evolução cardíaca e respiratória a cada turno',
        ],
        'alertas': 'Vigilância para edema agudo de pulmão. Comunicar médico se piora respiratória ou oligúria.',
    },

    # ── SEPSE ───────────────────────────────────────────────
    'sepse_tto': {
        'cids': ['a41','r57.2','sepse','choque séptico'],
        'classificacao': 'Sepse / Choque séptico — Bundle',
        'itens': [
            '1. Monitorar sinais vitais HORÁRIOS: PA, FC, FR, T°, SpO2 — registrar tendências',
            '2. Avaliar perfusão periférica horária: TEC, temperatura extremidades, nível de consciência',
            '3. Manter 2 acessos venosos calibrosos — garantir infusão de volume e antibióticos',
            '4. COLETAR HEMOCULTURAS (2 pares) ANTES do primeiro antibiótico — não atrasar ATB',
            '5. Administrar antibioticoterapia de amplo espectro na PRIMEIRA HORA (Bundle Sepse)',
            '6. Iniciar reposição volêmica: cristaloide 30ml/kg em até 3 horas conforme prescrição',
            '7. Monitorar DIURESE HORÁRIA — meta >0,5ml/kg/h — instalar SVD se necessário',
            '8. Realizar balanço hídrico rigoroso HORÁRIO',
            '9. Monitorar lactato sérico seriado conforme prescrição',
            '10. Avaliar nível de consciência com Glasgow a cada hora',
            '11. Monitorar exames laboratoriais: hemograma, PCR, lactato, creatinina, bilirrubinas',
            '12. Administrar vasopressores (noradrenalina) conforme prescrição se hipotensão refratária',
            '13. Controlar temperatura: antitérmico se T>38,5°C, aquecimento se hipotermia',
            '14. Avaliar necessidade de suporte ventilatório — preparar material para IOT',
            '15. Registrar TODOS os parâmetros do Bundle Sepse e horários',
            '16. Comunicar médico IMEDIATAMENTE qualquer deterioração hemodinâmica',
        ],
        'alertas': 'URGÊNCIA: Bundle Sepse — antibiótico na 1ª hora é meta obrigatória. Colher hemoculturas ANTES.',
    },

    # ── DIABETES ────────────────────────────────────────────
    'diabetes_tto': {
        'cids': ['e10','e11','e13','e14','diabetes','cetoacidose','hiperglicemia'],
        'classificacao': 'Diabetes mellitus descompensado / Cetoacidose',
        'itens': [
            '1. Monitorar glicemia capilar conforme prescrição (ex: 2/2h ou 6/6h)',
            '2. Administrar insulina conforme protocolo institucional e prescrição médica',
            '3. Avaliar e registrar sinais de hipoglicemia: sudorese fria, tremores, confusão, taquicardia',
            '4. Avaliar e registrar sinais de hiperglicemia: poliúria, polidipsia, náuseas, hálito cetônico',
            '5. Monitorar diurese: volume e frequência — atenção para poliúria',
            '6. Realizar balanço hídrico rigoroso — repor perdas conforme prescrição',
            '7. Monitorar eletrólitos: potássio sérico (insulinoterapia causa hipocalemia)',
            '8. Inspecionar extremidades diariamente: lesões, eritema, temperatura',
            '9. Realizar cuidados com feridas diabéticas conforme protocolo de curativos',
            '10. Administrar hidratação venosa conforme prescrição (SF 0,9% na CAD)',
            '11. Monitorar gasometria e cetonemia se cetoacidose',
            '12. Avaliar nível de consciência a cada turno',
            '13. Orientar sobre dieta hipoglicídica e importância da adesão ao tratamento',
            '14. Registrar evolução metabólica com valores de glicemia a cada turno',
            '15. Comunicar médico se glicemia <70mg/dL ou >300mg/dL',
        ],
        'alertas': 'Vigilância para hipoglicemia grave (<40mg/dL) e cetoacidose. Comunicar médico imediatamente.',
    },

    # ── RENAL ────────────────────────────────────────────────
    'ira_tto': {
        'cids': ['n17','insuficiência renal aguda','ira'],
        'classificacao': 'Insuficiência Renal Aguda',
        'itens': [
            '1. Monitorar diurese HORÁRIA — registrar volume, cor e características',
            '2. Instalar SVD se necessário para controle preciso de diurese',
            '3. Realizar balanço hídrico RIGOROSO — registrar toda ingesta e excreta',
            '4. Pesar paciente diariamente em jejum — comunicar variações >1kg',
            '5. Restringir ingesta hídrica e de potássio conforme prescrição',
            '6. Monitorar PA a cada 2-4 horas',
            '7. Monitorar eletrólitos: hipercalemia (K>6,5 — URGÊNCIA cardíaca)',
            '8. Avaliar sinais de hipercalemia: fraqueza muscular, arritmias, paresia',
            '9. Monitorar nível de ureia e creatinina conforme solicitação',
            '10. Cuidados com acesso para diálise (cateter, FAV): curativo estéril, permeabilidade',
            '11. Administrar diurético EV se prescrito — avaliar resposta diurética',
            '12. Evitar medicamentos nefrotóxicos — alertar equipe',
            '13. Monitorar sinais de edema agudo de pulmão: dispneia, crepitações',
            '14. Avaliar nível de consciência — uremia pode causar encefalopatia',
            '15. Registrar evolução renal com valores laboratoriais a cada turno',
        ],
        'alertas': 'Hipercalemia >6,5 mEq/L é emergência cardíaca. Comunicar médico imediatamente.',
    },
}


def _obter_prescricao_por_cid(diag_completo, queixas=''):
    """
    Busca prescrição clínica específica para o CID/diagnóstico.
    Retorna lista de itens clínicos individualizados + alertas.
    Dengue Tipo C recebe tratamento especial com vigilância intensiva.
    """
    d = diag_completo.lower()
    q = queixas.lower()

    # Dengue — classificação por gravidade (prioridade máxima)
    if any(x in d for x in ['dengue','a90','a91','a97']):
        # Verificar classificação de gravidade
        if any(x in d+q for x in ['tipo c','tipo d','grave','hemorrágica','hemorragica','choque',
                                    'a91','a97.2','sangramento ativo','plaquetas','trombocitopenia']):
            return PRESCRICOES_POR_CID['dengue_grave']
        elif any(x in d+q for x in ['sinais de alarme','tipo b','a97.1','dor abdominal intensa',
                                     'vômitos persistentes','letargia','oligúria']):
            return PRESCRICOES_POR_CID['dengue_alarme']
        else:
            return PRESCRICOES_POR_CID['dengue_classica']

    # Busca nas demais patologias
    for chave, dados in PRESCRICOES_POR_CID.items():
        if chave.startswith('dengue'): continue  # dengue já tratada acima
        for termo in dados['cids']:
            if termo in d:
                return dados

    return None  # Não encontrado — usar prompt genérico da IA



# ────────────────────────────────────────────────────────────
# BANCO NANDA-I 2024-2026 — Associação CID-10 → NANDA
# Estrutura: nanda1-5 (prioritários), fatores, plano, noc
# Individualizado por CID + quadro clínico do paciente
# ────────────────────────────────────────────────────────────

# Banco estruturado: cada entrada tem até 5 diagnósticos NANDA
# com fatores relacionados, características definidoras e NOC
NANDA_POR_CID = {
    # ── DOENÇAS INFECCIOSAS / TROPICAIS ─────────────────────
    'dengue': {
        'cids': ['a90','a91','a97','dengue','febre dengue'],
        'diagnosticos': [
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'processo infeccioso pelo vírus Dengue','evidenciado':'temperatura >38.5°C, calafrios, pele quente'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'processo inflamatório viral — mialgia e artralgia','evidenciado':'relato de dor, fácies de dor, EVA >3'},
            {'codigo':'00028','nome':'Risco de volume de líquidos deficiente','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'perda hídrica por febre e vômitos, extravasamento plasmático','evidenciado':'febre persistente, náuseas, vômitos'},
            {'codigo':'00206','nome':'Risco de sangramento','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'trombocitopenia por infecção viral','evidenciado':'plaquetas reduzidas, petéquias, prova do laço positiva'},
            {'codigo':'00093','nome':'Fadiga','dominio':'4 — Atividade/Repouso','classe':'3 — Equilíbrio de energia',
             'relacionado':'estado hipermetabólico da infecção viral','evidenciado':'relato de cansaço extremo, prostração'},
        ],
        'plano':'hidratação oral/EV rigorosa, controle temperatura 4/4h, monitorar plaquetas, observar sinais de alarme (dor abdominal intensa, vômitos persistentes, sangramentos), repouso relativo, paracetamol (NUNCA AAS/ibuprofeno), balanço hídrico, prova do laço',
        'noc':'Termorregulação (0800) meta T<37.8°C; Estado hídrico (0602); Controle do risco de sangramento (1922)'
    },
    'chikungunya': {
        'cids': ['a92','chikungunya'],
        'diagnosticos': [
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'processo inflamatório articular pelo vírus Chikungunya','evidenciado':'artralgia intensa, limitação de movimento, EVA >5'},
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'processo infeccioso viral','evidenciado':'febre >38.5°C, calafrios'},
            {'codigo':'00085','nome':'Mobilidade física prejudicada','dominio':'4 — Atividade/Repouso','classe':'2 — Atividade/Exercício',
             'relacionado':'artralgia e artrite aguda','evidenciado':'dificuldade de deambulação, rigidez articular'},
            {'codigo':'00093','nome':'Fadiga','dominio':'4 — Atividade/Repouso','classe':'3 — Equilíbrio de energia',
             'relacionado':'processo infeccioso e dor crônica','evidenciado':'relato de cansaço, prostração'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre a doença e prevenção','evidenciado':'perguntas frequentes, comportamento inadequado'},
        ],
        'plano':'analgesia conforme prescrição, repouso articular, fisioterapia precoce, hidratação, controle de temperatura, orientar sobre cronicidade da artralgia, NUNCA AAS',
        'noc':'Nível de dor (2102); Mobilidade (0208); Termorregulação (0800)'
    },
    'zika': {
        'cids': ['a92.8','zika'],
        'diagnosticos': [
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'infecção viral pelo Zika vírus','evidenciado':'febre baixa, exantema'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'processo inflamatório viral','evidenciado':'cefaleia, mialgia, artralgia'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'risco de complicações neurológicas e em gestantes','evidenciado':'expressão de preocupação, inquietação'},
        ],
        'plano':'hidratação, analgesia, repouso, orientar gestantes sobre risco de microcefalia, acompanhamento pré-natal rigoroso se gestante',
        'noc':'Termorregulação (0800); Nível de ansiedade (1211); Nível de dor (2102)'
    },
    # ── RESPIRATÓRIO ────────────────────────────────────────
    'asma': {
        'cids': ['j45','j46','asma','broncoespas','crise asmat','status asmat'],
        'diagnosticos': [
            {'codigo':'00032','nome':'Padrão respiratório ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'broncoespasmo e inflamação das vias aéreas','evidenciado':'dispneia, sibilos, uso de musculatura acessória'},
            {'codigo':'00030','nome':'Troca de gases prejudicada','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'desequilíbrio ventilação-perfusão','evidenciado':'SpO2 reduzida, dispneia, ansiedade'},
            {'codigo':'00039','nome':'Risco de aspiração','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'reflexo de tosse alterado durante crise','evidenciado':'crise asmática grave, nível de consciência alterado'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'dificuldade respiratória e medo','evidenciado':'expressão de medo, agitação, taquicardia'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre uso correto de dispositivos inalatórios','evidenciado':'técnica incorreta de inalação'},
        ],
        'plano':'posição Fowler 45°, broncodilatadores conforme prescrição, oximetria contínua meta SpO2>95%, nebulização, ausculta 2/2h, evitar fatores desencadeantes, técnica de respiração com lábios franzidos',
        'noc':'Estado respiratório: ventilação (0403) SpO2>95%; Controle de sintomas (1608); Nível de ansiedade (1211)'
    },
    'dpoc': {
        'cids': ['j44','j43','dpoc','doença pulmonar obstrutiva','enfisema'],
        'diagnosticos': [
            {'codigo':'00030','nome':'Troca de gases prejudicada','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'destruição do parênquima pulmonar e aprisionamento de ar','evidenciado':'SpO2 88-92%, dispneia, cianose labial'},
            {'codigo':'00032','nome':'Padrão respiratório ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'obstrução crônica ao fluxo aéreo e fadiga da musculatura respiratória','evidenciado':'uso musculatura acessória, taquipneia, barrel chest'},
            {'codigo':'00092','nome':'Intolerância à atividade','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'desequilíbrio entre oferta e demanda de O2','evidenciado':'dispneia ao esforço, fadiga, incapacidade de realizar AVDs'},
            {'codigo':'00155','nome':'Risco de quedas','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'hipoxemia e fraqueza muscular','evidenciado':'tontura, fraqueza, uso de O2 suplementar'},
            {'codigo':'00078','nome':'Gerenciamento ineficaz da saúde','dominio':'1 — Promoção da saúde','classe':'2 — Gerenciamento da saúde',
             'relacionado':'complexidade do regime terapêutico e tabagismo','evidenciado':'falha na adesão ao tratamento, tabagismo ativo'},
        ],
        'plano':'semi-Fowler 30-45°, O2 controlado meta SpO2 88-92% (CUIDADO retenção CO2), fisioterapia respiratória, respiração com lábios franzidos, nebulização broncodilatadora, monitorar sonolência/confusão',
        'noc':'Estado respiratório: troca gasosa (0402); Tolerância à atividade (0005); Autocontrole DPOC (3200)'
    },
    'pneumonia': {
        'cids': ['j18','j15','j12','j14','j13','pneumonia'],
        'diagnosticos': [
            {'codigo':'00030','nome':'Troca de gases prejudicada','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'processo inflamatório alveolar com exsudato','evidenciado':'SpO2 reduzida, dispneia, crepitações à ausculta'},
            {'codigo':'00031','nome':'Limpeza ineficaz das vias aéreas','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'secreção excessiva e tosse ineficaz','evidenciado':'roncos, estertores, tosse produtiva'},
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'processo infeccioso bacteriano/viral','evidenciado':'febre >38.5°C, calafrios, sudorese'},
            {'codigo':'00032','nome':'Padrão respiratório ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'dor pleurítica e fraqueza muscular','evidenciado':'taquipneia, respiração superficial'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'procedimentos invasivos e imunossupressão','evidenciado':'dispositivos invasivos, leucocitose'},
        ],
        'plano':'cabeceira 30-45°, ATB rigorosa no horário, controle temperatura 4/4h, fisioterapia respiratória, incentivar expectoração, hidratação, oximetria contínua, coleta de culturas',
        'noc':'Troca gasosa (0402); Permeabilidade vias aéreas (0410); Termorregulação (0800)'
    },
    'insuf_resp': {
        'cids': ['j96','sara','sdra','insuficiência respiratória'],
        'diagnosticos': [
            {'codigo':'00030','nome':'Troca de gases prejudicada','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'falência da membrana alvéolo-capilar','evidenciado':'SpO2 crítica, gasometria alterada, cianose'},
            {'codigo':'00032','nome':'Padrão respiratório ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'fadiga da musculatura respiratória','evidenciado':'taquipneia >30rpm, uso intenso musculatura acessória'},
            {'codigo':'00039','nome':'Risco de aspiração','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'nível de consciência reduzido e intubação','evidenciado':'rebaixamento de consciência, IOT'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'dispneia intensa e sensação de morte iminente','evidenciado':'agitação, taquicardia, expressão de medo'},
        ],
        'plano':'monitorar gasometria e oximetria, cabeceira 30-45°, O2 alto fluxo, preparar material IOT, aspiração vias aéreas, monitorar consciência, posição prona se indicada',
        'noc':'Estado respiratório: troca gasosa (0402); Permeabilidade vias aéreas (0410); Nível consciência (0912)'
    },
    # ── CARDIOVASCULAR ──────────────────────────────────────
    'iam': {
        'cids': ['i21','i22','infarto','iam','supra de st','iamsst'],
        'diagnosticos': [
            {'codigo':'00029','nome':'Débito cardíaco diminuído','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'necrose miocárdica e disfunção ventricular','evidenciado':'hipotensão, taquicardia, alteração ECG'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'isquemia miocárdica','evidenciado':'dor precordial em aperto, irradiação para membro superior esquerdo, EVA >7'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'ameaça à vida e ambiente da UTI/UCC','evidenciado':'expressão de medo, agitação'},
            {'codigo':'00204','nome':'Perfusão tissular periférica ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'débito cardíaco reduzido','evidenciado':'extremidades frias, pulso fraco, cianose de extremidades'},
            {'codigo':'00206','nome':'Risco de sangramento','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'uso de anticoagulantes e antiagregantes','evidenciado':'terapia anticoagulante em curso'},
        ],
        'plano':'repouso absoluto 12-24h, monitoração cardíaca contínua, acesso venoso calibroso, controle da dor EVA, antiagregantes/anticoagulantes no horário, ECG seriado, enzimas cardíacas, O2 se SpO2<95%',
        'noc':'Estado cardíaco (0414); Nível de dor (2102); Nível de ansiedade (1211)'
    },
    'icc': {
        'cids': ['i50','insuficiência cardíaca','icc'],
        'diagnosticos': [
            {'codigo':'00029','nome':'Débito cardíaco diminuído','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'disfunção sistólica/diastólica ventricular','evidenciado':'dispneia, edema MMII, B3, turgência jugular'},
            {'codigo':'00026','nome':'Excesso de volume de líquidos','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'mecanismos compensatórios de retenção hidrossalina','evidenciado':'edema MMII, crepitações pulmonares, ganho de peso'},
            {'codigo':'00092','nome':'Intolerância à atividade','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'desequilíbrio entre oferta e demanda de O2','evidenciado':'dispneia aos pequenos esforços, fadiga'},
            {'codigo':'00032','nome':'Padrão respiratório ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'congestão pulmonar','evidenciado':'ortopneia, dispneia paroxística noturna'},
            {'codigo':'00155','nome':'Risco de quedas','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'hipotensão postural e fraqueza muscular','evidenciado':'uso de diuréticos, tontura'},
        ],
        'plano':'MMII elevados 30°, restrição hídrica conforme prescrição, diurese rigorosa balanço hídrico, pesagem diária, monitorar edema/crepitações, restrição sódio, O2 se SpO2<95%',
        'noc':'Efetividade bomba cardíaca (0400); Equilíbrio hídrico (0601); Tolerância atividade (0005)'
    },
    'has': {
        'cids': ['i10','i11','hipertensão','has','pressão alta','crise hipertensiva'],
        'diagnosticos': [
            {'codigo':'00201','nome':'Risco de perfusão tissular cerebral ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'pressão arterial elevada','evidenciado':'PA >180/110mmHg, cefaleia, tontura'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'vasoespasmo cerebral','evidenciado':'cefaleia occipital intensa, EVA >5'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre adesão ao tratamento','evidenciado':'abandono da medicação, comportamentos de risco'},
            {'codigo':'00078','nome':'Gerenciamento ineficaz da saúde','dominio':'1 — Promoção da saúde','classe':'2 — Gerenciamento da saúde',
             'relacionado':'complexidade do regime terapêutico','evidenciado':'PA não controlada, falha na adesão'},
        ],
        'plano':'monitorar PA ambos os membros, repouso ambiente calmo, anti-hipertensivos conforme prescrição, monitorar sinais neurológicos, restrição sódio, orientar adesão ao tratamento',
        'noc':'Estado neurológico (0909); Nível de dor (2102); Conhecimento: controle da doença crônica (1847)'
    },
    'avc': {
        'cids': ['i60','i61','i63','i64','avc','acidente vascular','derrame'],
        'diagnosticos': [
            {'codigo':'00201','nome':'Perfusão tissular cerebral ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'oclusão/ruptura vascular cerebral','evidenciado':'déficit neurológico focal, Glasgow alterado'},
            {'codigo':'00039','nome':'Risco de aspiração','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'disfagia e reflexo de tosse reduzido','evidenciado':'deglutição prejudicada, nível de consciência alterado'},
            {'codigo':'00085','nome':'Mobilidade física prejudicada','dominio':'4 — Atividade/Repouso','classe':'2 — Atividade/Exercício',
             'relacionado':'dano neuromuscular','evidenciado':'hemiplegia/hemiparesia, espasticidade'},
            {'codigo':'00011','nome':'Constipação','dominio':'3 — Eliminação/Troca','classe':'2 — Função gastrointestinal',
             'relacionado':'imobilidade e hidratação inadequada','evidenciado':'ausência de evacuação >3 dias'},
            {'codigo':'00108','nome':'Déficit no autocuidado para banho','dominio':'4 — Atividade/Repouso','classe':'5 — Autocuidado',
             'relacionado':'déficit neuromuscular','evidenciado':'incapacidade de realizar higiene corporal'},
        ],
        'plano':'cabeceira 30°, Glasgow 2/2h, avaliação pupilas/força/fala, posicionamento anti-contraturas, fisioterapia motora precoce, teste deglutição antes dieta oral, profilaxia TVP, fonoaudiologia',
        'noc':'Perfusão tissular cerebral (0406); Estado neurológico (0909); Mobilidade (0208)'
    },
    # ── NEUROLÓGICO ─────────────────────────────────────────
    'tce': {
        'cids': ['s06','tce','traumatismo cranio','trauma cranioence'],
        'diagnosticos': [
            {'codigo':'00049','nome':'Capacidade de recuperação intracraniana diminuída','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'edema cerebral traumático','evidenciado':'Glasgow reduzido, cefaleia intensa, vômitos'},
            {'codigo':'00201','nome':'Risco de perfusão tissular cerebral ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'hipertensão intracraniana','evidenciado':'alteração pupilares, Cushing reflex'},
            {'codigo':'00039','nome':'Risco de aspiração','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'nível de consciência reduzido','evidenciado':'Glasgow <10, reflexo de tosse diminuído'},
            {'codigo':'00155','nome':'Risco de quedas','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'confusão e agitação pós-TCE','evidenciado':'desorientação, agitação psicomotora'},
        ],
        'plano':'cabeceira 30°, Glasgow 1/1h, pupilas, PA rigorosa evitar hipotensão, sinais herniação, restrição hídrica se prescrito, grades elevadas, ambiente calmo, profilaxia convulsão',
        'noc':'Estado neurológico: consciência (0912); Perfusão tissular cerebral (0406); Controle do risco (1902)'
    },
    'epilepsia': {
        'cids': ['g40','g41','epilepsia','convuls','status epilept'],
        'diagnosticos': [
            {'codigo':'00035','nome':'Risco de lesão','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'atividade convulsiva súbita','evidenciado':'história de convulsões, ausência de medicação'},
            {'codigo':'00039','nome':'Risco de aspiração','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'perda de consciência durante crise','evidenciado':'rebaixamento de consciência pós-ictal'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'medo de nova crise e imprevisibilidade','evidenciado':'expressão de preocupação, isolamento'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre manejo da crise','evidenciado':'acompanhantes sem conhecimento de primeiros socorros'},
        ],
        'plano':'grades elevadas, ambiente protegido, anticonvulsivante no horário, decúbito lateral após crise, O2 disponível, NÃO conter movimentos, monitorar pós-ictal, orientar família',
        'noc':'Controle do risco (1902); Estado respiratório (0403); Nível ansiedade (1211)'
    },
    # ── METABÓLICO / ENDÓCRINO ──────────────────────────────
    'diabetes': {
        'cids': ['e10','e11','e13','e14','diabetes','dm ','glicemia','hiperglicemia','hipoglicemia','cetoacidose'],
        'diagnosticos': [
            {'codigo':'00179','nome':'Nível de glicemia instável','dominio':'2 — Nutrição','classe':'4 — Metabolismo',
             'relacionado':'deficiência ou resistência à insulina','evidenciado':'glicemia capilar alterada, poliúria, polidipsia'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'imunossupressão por hiperglicemia','evidenciado':'hiperglicemia persistente, feridas de difícil cicatrização'},
            {'codigo':'00226','nome':'Risco de perfusão tissular periférica ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'neuropatia e vasculopatia diabética','evidenciado':'diminuição de sensibilidade, pulsos reduzidos'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre autocuidado e dieta','evidenciado':'alimentação inadequada, não realização de glicemia capilar'},
            {'codigo':'00193','nome':'Autogerenciamento ineficaz da saúde','dominio':'1 — Promoção da saúde','classe':'2 — Gerenciamento da saúde',
             'relacionado':'complexidade do regime terapêutico','evidenciado':'HbA1c elevada, falha no uso de insulina'},
        ],
        'plano':'glicemia capilar 6/6h, insulina conforme protocolo, monitorar hipo/hiperglicemia, inspecionar pés/extremidades diariamente, cuidados com feridas, orientar dieta e exercício',
        'noc':'Nível de glicemia (2300); Controle risco infeccioso (1924); Conhecimento: controle DM (1820)'
    },
    'sepse': {
        'cids': ['a41','r57.2','sepse','choque séptico','séptico'],
        'diagnosticos': [
            {'codigo':'00204','nome':'Perfusão tissular periférica ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'vasodilatação periférica e hipovolemia relativa','evidenciado':'hipotensão, extremidades frias, TEC>3seg'},
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'processo infeccioso sistêmico','evidenciado':'temperatura >38.5°C ou hipotermia <36°C'},
            {'codigo':'00205','nome':'Risco de choque','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'infecção grave e disfunção orgânica','evidenciado':'lactato elevado, PA limítrofe, oligúria'},
            {'codigo':'00030','nome':'Troca de gases prejudicada','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'edema pulmonar e vasoplegia','evidenciado':'taquipneia, SpO2 reduzida'},
            {'codigo':'00002','nome':'Nutrição desequilibrada: menor que as necessidades','dominio':'2 — Nutrição','classe':'1 — Ingestão',
             'relacionado':'hipermetabolismo do estado séptico','evidenciado':'catabolismo elevado, perda de peso'},
        ],
        'plano':'SVs 1/1h, diurese meta>0.5ml/kg/h, culturas antes ATB, ATB dentro do prazo (bundle sepse), acesso calibroso, reposição volêmica 30ml/kg, lactato seriado, noradrenalina se prescrita',
        'noc':'Perfusão tissular periférica (0407); Termorregulação (0800); Estado circulatório (0401)'
    },
    # ── RENAL ────────────────────────────────────────────────
    'renal': {
        'cids': ['n17','n18','ira','irc','insuficiência renal','diálise','renal aguda','renal crônica'],
        'diagnosticos': [
            {'codigo':'00016','nome':'Eliminação urinária prejudicada','dominio':'3 — Eliminação/Troca','classe':'1 — Função urinária',
             'relacionado':'disfunção renal aguda/crônica','evidenciado':'oligúria/anúria, creatinina elevada, ureia aumentada'},
            {'codigo':'00026','nome':'Excesso de volume de líquidos','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'comprometimento dos mecanismos regulatórios renais','evidenciado':'edema, hipertensão, dispneia'},
            {'codigo':'00195','nome':'Risco de desequilíbrio eletrolítico','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'falência da regulação eletrolítica renal','evidenciado':'hipercalemia, hiperfosfatemia'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'uremia e procedimentos invasivos','evidenciado':'relato de dor, fácies de dor'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'imunossupressão e acesso para diálise','evidenciado':'cateter de diálise, imunossupressão'},
        ],
        'plano':'diurese horária rigorosa, balanço hídrico, restrição hídrica/potássio conforme prescrição, pesagem diária, eletrólitos seriados, sinais hipercalemia (arritmias), cuidados acesso diálise',
        'noc':'Eliminação urinária (0503); Equilíbrio hídrico (0601); Equilíbrio eletrolítico (0606)'
    },
    # ── GASTROINTESTINAL ────────────────────────────────────
    'pancreatite': {
        'cids': ['k85','pancreatite'],
        'diagnosticos': [
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'inflamação pancreática e irritação peritoneal','evidenciado':'dor epigástrica intensa em faixa, EVA >8, vômitos'},
            {'codigo':'00002','nome':'Nutrição desequilibrada: menor que as necessidades','dominio':'2 — Nutrição','classe':'1 — Ingestão',
             'relacionado':'jejum prolongado e hipermetabolismo','evidenciado':'jejum, náuseas, perda de peso'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'necrose pancreática e procedimentos invasivos','evidenciado':'febre, leucocitose, cateter EV'},
            {'codigo':'00026','nome':'Excesso de volume de líquidos','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'sequestro de líquidos no terceiro espaço','evidenciado':'edema, hipoalbuminemia'},
        ],
        'plano':'jejum conforme prescrição, analgesia EVA, reposição volêmica rigorosa, monitorar amilase/lipase, posição confortável joelhos fletidos, nutrição enteral se indicada, controle glicêmico',
        'noc':'Nível de dor (2102); Estado nutricional (1004); Controle infecção (1924)'
    },
    'hemorragia_dig': {
        'cids': ['k92','k25','k26','melena','hematêmese','hemorragia digestiva'],
        'diagnosticos': [
            {'codigo':'00204','nome':'Perfusão tissular periférica ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'hipovolemia por sangramento ativo','evidenciado':'hipotensão, taquicardia, palidez, TEC>3seg'},
            {'codigo':'00205','nome':'Risco de choque','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'perda volêmica aguda','evidenciado':'melena/hematêmese ativa, hemoglobina em queda'},
            {'codigo':'00206','nome':'Risco de sangramento','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'lesão vascular gastrointestinal','evidenciado':'sangramento ativo, coagulopatia'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'ameaça à vida e procedimentos invasivos','evidenciado':'agitação, medo'},
        ],
        'plano':'acesso venoso calibroso, reposição volêmica, jejum absoluto, monitorar PA/FC, preparar para endoscopia, Hb/Ht seriados, decúbito dorsal, inibidor de bomba de prótons',
        'noc':'Estado circulatório (0401); Controle risco (1902); Nível ansiedade (1211)'
    },
    # ── ONCOLÓGICO ──────────────────────────────────────────
    'cancer': {
        'cids': ['c18','c34','c50','c61','c67','c80','c91','c92','z51','neoplasia','câncer','tumor','leucemia','linfoma'],
        'diagnosticos': [
            {'codigo':'00093','nome':'Fadiga','dominio':'4 — Atividade/Repouso','classe':'3 — Equilíbrio de energia',
             'relacionado':'processo neoplásico e efeitos da quimioterapia/radioterapia','evidenciado':'relato de cansaço extremo, incapacidade para AVDs'},
            {'codigo':'00002','nome':'Nutrição desequilibrada: menor que as necessidades','dominio':'2 — Nutrição','classe':'1 — Ingestão',
             'relacionado':'anorexia, náuseas e hipermetabolismo neoplásico','evidenciado':'perda de peso >10%, albumina baixa, ingestão reduzida'},
            {'codigo':'00132','nome':'Dor aguda/crônica','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'invasão tumoral e neuropatia por quimioterapia','evidenciado':'EVA >5, relato de dor, uso de analgésicos'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'imunossupressão por quimioterapia e neutropenia','evidenciado':'neutropenia, mucosites, cateter venoso'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'diagnóstico de câncer e prognóstico incerto','evidenciado':'expressão de medo, insônia, choro'},
        ],
        'plano':'protocolo de neutropenia febril se indicado, analgesia escalonada OMS, nutrição enteral/parenteral se necessário, cuidados com mucosite, higiene rigorosa, apoio emocional e espiritual, oncologia social',
        'noc':'Estado nutricional (1004); Controle da dor (1605); Nível de ansiedade (1211)'
    },
    # ── ORTOPÉDICO / TRAUMA ─────────────────────────────────
    'fratura': {
        'cids': ['s72','s82','s52','s42','s32','s22','fratura','ortopédico','artroplastia','z96.6'],
        'diagnosticos': [
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'lesão musculoesquelética e espasmo muscular','evidenciado':'EVA >5, proteção da área lesada, limitação de movimento'},
            {'codigo':'00085','nome':'Mobilidade física prejudicada','dominio':'4 — Atividade/Repouso','classe':'2 — Atividade/Exercício',
             'relacionado':'dor, imobilização e perda de força muscular','evidenciado':'incapacidade de movimentar membro, dispositivo de imobilização'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'exposição óssea (fratura exposta) ou cirurgia','evidenciado':'ferida cirúrgica, fratura exposta'},
            {'codigo':'00291','nome':'Risco de trombose venosa profunda','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'imobilidade e lesão vascular','evidenciado':'imobilização de membro, cirurgia ortopédica'},
            {'codigo':'00155','nome':'Risco de quedas','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'imobilidade, dor e uso de analgésicos opioides','evidenciado':'mobilidade reduzida, uso de dispositivos de apoio'},
        ],
        'plano':'imobilização adequada, analgesia EVA, profilaxia TVP (HBPM + meias compressivas), fisioterapia precoce, cuidados com ferida cirúrgica, mobilização progressiva, grades elevadas',
        'noc':'Nível de dor (2102); Mobilidade (0208); Controle do risco TVP (1934)'
    },
    'queimadura': {
        'cids': ['t20','t21','t22','t23','t24','t25','t31','queimadura'],
        'diagnosticos': [
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'lesão térmica das terminações nervosas','evidenciado':'EVA elevada, expressão de dor, choro'},
            {'codigo':'00027','nome':'Déficit de volume de líquidos','dominio':'2 — Nutrição','classe':'5 — Hidratação',
             'relacionado':'perda de líquidos pela área queimada e edema de terceiro espaço','evidenciado':'hipotensão, taquicardia, oligúria'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'perda da barreira cutânea protetora','evidenciado':'área cruenta exposta, queimadura >20% SCQ'},
            {'codigo':'00046','nome':'Integridade tissular prejudicada','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'lesão térmica direta','evidenciado':'necrose tecidual, vesículas, eritema'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'dor intensa, desfiguramento e hospitalização','evidenciado':'agitação, medo, choro'},
        ],
        'plano':'reposição volêmica Parkland (4ml/kg/%SCQ nas 24h), analgesia potente, curativo estéril, profilaxia infecção, nutrição hipercalórica precoce, fisioterapia, apoio psicológico',
        'noc':'Estado hídrico (0602); Integridade tissular (1101); Controle infecção (1924)'
    },
    # ── OBSTÉTRICO ──────────────────────────────────────────
    'gestante': {
        'cids': ['o10','o14','o15','o20','o21','o24','o42','o60','o80','o82','gestante','gravidez','eclâmpsia','pré-eclâmpsia'],
        'diagnosticos': [
            {'codigo':'00206','nome':'Risco de sangramento','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'processo gestacional e complicações obstétricas','evidenciado':'sangramento vaginal, placenta prévia'},
            {'codigo':'00201','nome':'Risco de perfusão tissular cerebral ineficaz','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'hipertensão gestacional e eclâmpsia','evidenciado':'PA >140/90mmHg, cefaleia, escotomas'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'complicações gestacionais e risco ao feto','evidenciado':'preocupação com o bebê, medo do parto'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'contrações uterinas e processo do parto','evidenciado':'EVA variável, contrações regulares'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'rotura de membranas e procedimentos obstétricos','evidenciado':'rotura de membranas, procedimentos invasivos'},
        ],
        'plano':'monitoração fetal contínua, PA frequente, anti-hipertensivo se prescrito, magnésio se eclâmpsia, decúbito lateral esquerdo, sulfato de magnésio para prevenção de convulsões, preparo para parto',
        'noc':'Estado circulatório materno (0401); Nível de ansiedade (1211); Controle do risco (1902)'
    },
    # ── PSIQUIÁTRICO ────────────────────────────────────────
    'psiquiatrico': {
        'cids': ['f20','f30','f31','f32','f33','f40','f41','f43','f60','f10','f11','psiquiátrico','esquizofrenia','depressão','mania','ansiedade','transtorno'],
        'diagnosticos': [
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento/Tolerância ao estresse','classe':'2 — Respostas de enfrentamento',
             'relacionado':'ameaça à integridade do self e situações estressoras','evidenciado':'agitação, taquicardia, inquietação, verbalização de medo'},
            {'codigo':'00150','nome':'Risco de suicídio','dominio':'11 — Segurança/Proteção','classe':'3 — Violência',
             'relacionado':'transtorno mental grave e ideação suicida','evidenciado':'verbalização de ideação, tentativas anteriores'},
            {'codigo':'00054','nome':'Isolamento social','dominio':'12 — Conforto','classe':'3 — Conforto social',
             'relacionado':'alteração do estado mental e estigma','evidenciado':'isolamento, recusa de contato, comportamento retraído'},
            {'codigo':'00051','nome':'Comunicação verbal prejudicada','dominio':'5 — Percepção/Cognição','classe':'5 — Comunicação',
             'relacionado':'distúrbio psíquico e efeitos de psicofármacos','evidenciado':'fala desorganizada, pensamento tangencial'},
            {'codigo':'00079','nome':'Não adesão','dominio':'10 — Princípios da vida','classe':'3 — Congruência entre valores/crenças/ações',
             'relacionado':'falta de insight sobre a doença','evidenciado':'abandono da medicação, comportamento de risco'},
        ],
        'plano':'ambiente terapêutico seguro (retirar objetos cortantes), observação contínua se risco de suicídio, medicação no horário, abordar com comunicação terapêutica, envolver família, psicologia/psiquiatria',
        'noc':'Autocontrole da ansiedade (1402); Controle do pensamento distorcido (1403); Nível de ansiedade (1211)'
    },
    # ── TIREÓIDE ────────────────────────────────────────────
    'hipotireoidismo': {
        'cids': ['e03','hipotireoidismo'],
        'diagnosticos': [
            {'codigo':'00093','nome':'Fadiga','dominio':'4 — Atividade/Repouso','classe':'3 — Equilíbrio de energia',
             'relacionado':'redução do metabolismo basal','evidenciado':'cansaço extremo, sonolência excessiva, bradicardia'},
            {'codigo':'00011','nome':'Constipação','dominio':'3 — Eliminação/Troca','classe':'2 — Função gastrointestinal',
             'relacionado':'peristaltismo reduzido por hipometabolismo','evidenciado':'ausência de evacuação, distensão abdominal'},
            {'codigo':'00007','nome':'Hipotermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'redução da termogênese','evidenciado':'T<36°C, intolerância ao frio, pele fria e seca'},
        ],
        'plano':'monitorar temperatura, levotiroxina conforme prescrição, hidratação, dieta rica em fibras, orientar sobre adesão ao tratamento, evitar exposição ao frio',
        'noc':'Tolerância à atividade (0005); Eliminação intestinal (0501); Termorregulação (0800)'
    },
    'hipertireoidismo': {
        'cids': ['e05','hipertireoidismo','tireotoxicose','basedow'],
        'diagnosticos': [
            {'codigo':'00029','nome':'Débito cardíaco diminuído','dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
             'relacionado':'taquicardia e arritmias por excesso hormonal','evidenciado':'FC>100bpm, fibrilação atrial'},
            {'codigo':'00093','nome':'Fadiga','dominio':'4 — Atividade/Repouso','classe':'3 — Equilíbrio de energia',
             'relacionado':'hipermetabolismo','evidenciado':'fraqueza muscular, intolerância ao exercício'},
            {'codigo':'00007','nome':'Hipertermia','dominio':'11 — Segurança/Proteção','classe':'6 — Termorregulação',
             'relacionado':'aumento da termogênese','evidenciado':'sudorese excessiva, temperatura elevada, intolerância ao calor'},
        ],
        'plano':'monitoração cardíaca, beta-bloqueador conforme prescrição, antitireoidiano no horário, ambiente fresco, repouso, nutrição hipercalórica, observar crise tireotóxica',
        'noc':'Estado cardíaco (0414); Tolerância à atividade (0005); Termorregulação (0800)'
    },
    # ── DERMATOLÓGICO / PELE ────────────────────────────────
    'lesao_pressao': {
        'cids': ['l89','lesão por pressão','úlcera de pressão','escara'],
        'diagnosticos': [
            {'codigo':'00046','nome':'Integridade tissular prejudicada','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'pressão prolongada e isquemia tecidual','evidenciado':'solução de continuidade da pele, necrose'},
            {'codigo':'00047','nome':'Integridade da pele prejudicada','dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
             'relacionado':'umidade, fricção e pressão','evidenciado':'eritema não branqueável, maceração'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'solução de continuidade da pele','evidenciado':'ferida aberta, sinais de infecção'},
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'exposição de terminações nervosas','evidenciado':'relato de dor na ferida, EVA'},
        ],
        'plano':'mudança de decúbito 2/2h, colchão piramidal/pneumático, curativo conforme protocolo, hidratação da pele perilesional, nutrição adequada (proteínas/zinco/vitamina C), registro fotográfico, escala Braden',
        'noc':'Integridade tissular (1101); Cicatrização de feridas (1103); Controle do risco (1902)'
    },
}

def _mapear_nanda_por_patologia(diag_completo):
    """
    Mapeia diagnóstico médico/CID-10 → banco NANDA-I 2024-2026 individualizado.
    Retorna dict com nanda1-5, plano e noc específicos para a patologia.
    Cada paciente recebe diagnósticos baseados no CID e quadro clínico real.
    """
    d = diag_completo.lower()

    # Buscar no banco estruturado
    for chave, dados in NANDA_POR_CID.items():
        for termo in dados['cids']:
            if termo in d:
                diags = dados['diagnosticos']
                return {
                    'nanda1': f"{diags[0]['nome']} (NANDA {diags[0]['codigo']}) — {diags[0]['dominio']}",
                    'nanda2': f"{diags[1]['nome']} (NANDA {diags[1]['codigo']}) — {diags[1]['dominio']}" if len(diags)>1 else '',
                    'nanda3': f"{diags[2]['nome']} (NANDA {diags[2]['codigo']}) — {diags[2]['dominio']}" if len(diags)>2 else '',
                    'nanda4': f"{diags[3]['nome']} (NANDA {diags[3]['codigo']}) — {diags[3]['dominio']}" if len(diags)>3 else '',
                    'nanda5': f"{diags[4]['nome']} (NANDA {diags[4]['codigo']}) — {diags[4]['dominio']}" if len(diags)>4 else '',
                    'diagnosticos_completos': diags,
                    'plano': dados['plano'],
                    'noc': dados['noc'],
                    'patologia_identificada': chave
                }

    # DEFAULT clínico — quando não identifica patologia específica
    return {
        'nanda1': 'Dor aguda (NANDA 00132) — Domínio 12, Classe 1',
        'nanda2': 'Risco de infecção (NANDA 00004) — Domínio 11, Classe 1',
        'nanda3': 'Ansiedade (NANDA 00146) — Domínio 9, Classe 2',
        'nanda4': 'Deficiência de conhecimento (NANDA 00126) — Domínio 5, Classe 4',
        'nanda5': '',
        'diagnosticos_completos': [],
        'plano': 'monitorar sinais vitais, administrar medicamentos conforme prescrição, observar evolução clínica, manter conforto e segurança, orientar paciente e família',
        'noc': 'Nível de dor (2102); Controle do risco (1902); Nível de ansiedade (1211)',
        'patologia_identificada': 'default'
    }


def _montar_prompt_prescricao(p, diag_completo, nc, ctx, dispositivos, pendencias, nanda_selecionados=''):
    """
    Monta prompt de prescrição individualizado baseado no banco clínico.
    Para Dengue: classifica automaticamente por gravidade (A/B/C/D).
    Para todas as patologias: usa itens clínicos específicos do banco.
    """
    # Buscar banco de prescrições específico para este CID
    banco = _obter_prescricao_por_cid(diag_completo, p.get('queixas',''))

    if banco:
        # Temos prescrições clínicas específicas no banco
        itens_banco = "\n".join(banco['itens'])
        classificacao = banco.get('classificacao','')
        alertas = banco.get('alertas','')

        return f"""Você é enfermeiro(a) especialista em SAE. Complete a PRESCRIÇÃO DE ENFERMAGEM abaixo com base nos dados reais do paciente.
{ctx}

DADOS DO PACIENTE:
Nome: {p.get('nome')} | Leito: {p.get('leito')}
Diagnóstico Médico: {diag_completo}
Classificação: {classificacao}
Sinais Vitais: {p.get('sv')}
Queixas/Estado Clínico: {p.get('queixas')}
Dispositivos: {dispositivos or p.get('exames','')}
Alergias: {p.get('alergias','')}
Diagnóstico NANDA Prioritário: {nc['nanda1']}
{'DIAGNÓSTICOS NANDA SELECIONADOS PELO ENFERMEIRO: ' + nanda_selecionados if nanda_selecionados else ''}

{alertas}

INSTRUÇÃO: Use os itens base abaixo e PERSONALIZE com os dados reais do paciente (SVs, queixas, exames, dispositivos).
Adicione horários específicos. Remova itens não aplicáveis. Adicione itens clínicos relevantes para este paciente específico.
NUNCA gere texto genérico igual para todos os pacientes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRESCRIÇÃO DE ENFERMAGEM
Data: ___/___/______ Turno: ( )Manhã ( )Tarde ( )Noite
Paciente: {p.get('nome')} | Leito: {p.get('leito')}
Diagnóstico: {diag_completo} — {classificacao}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DIAGNÓSTICOS DE ENFERMAGEM (NANDA-I 2024-2026):
1. {nc['nanda1']}
   Relacionado a: [personalizar com dados reais]
   Evidenciado por: [usar SVs e queixas reais: {p.get('sv')} / {p.get('queixas')}]
2. {nc['nanda2']}

PRESCRIÇÕES BASE (personalize com dados do paciente):
{itens_banco}

PERSONALIZAÇÕES OBRIGATÓRIAS para {p.get('nome')}:
- Adaptar frequências de monitoramento aos SVs atuais: {p.get('sv')}
- Incluir cuidados específicos para dispositivos: {dispositivos or p.get('exames','')}
- Relacionar com queixas do paciente: {p.get('queixas')}
- Adicionar no mínimo 2 itens personalizados baseados no quadro clínico acima

PENDÊNCIAS DO TURNO: {pendencias}

RESULTADOS ESPERADOS (NOC): {nc['noc']}

Enfermeiro(a): _________________________ COREN: _________"""

    else:
        # Patologia não mapeada — prompt genérico melhorado
        return f"""Você é enfermeiro(a) especialista em SAE. Gere PRESCRIÇÃO DE ENFERMAGEM individualizada.
{ctx}

DADOS DO PACIENTE:
Nome: {p.get('nome')} | Leito: {p.get('leito')}
Diagnóstico Médico: {diag_completo}
Sinais Vitais: {p.get('sv')}
Queixas: {p.get('queixas')}
Dispositivos: {dispositivos or p.get('exames','')}
Alergias: {p.get('alergias','')}
Diagnóstico NANDA: {nc['nanda1']}
{'Diagnósticos NANDA selecionados: ' + nanda_selecionados if nanda_selecionados else ''}
Pendências: {pendencias}

Intervenções base para {diag_completo}: {nc['plano']}

INSTRUÇÃO: Gere MÍNIMO 14 itens INDIVIDUALIZADOS para ESTE paciente específico.
Use os dados reais acima. NUNCA repita texto igual para pacientes diferentes.
Inclua horários específicos. Relacione cada item ao quadro clínico real.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRESCRIÇÃO DE ENFERMAGEM
Data: ___/___/______ Turno: ( )Manhã ( )Tarde ( )Noite
Paciente: {p.get('nome')} | Leito: {p.get('leito')}
Diagnóstico: {diag_completo}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

DIAGNÓSTICOS DE ENFERMAGEM (NANDA-I 2024-2026):
1. {nc['nanda1']}
   Relacionado a: [fator específico de {diag_completo}]
   Evidenciado por: [dados reais: {p.get('queixas')}]
2. {nc['nanda2']}

PRESCRIÇÃO — CUIDADOS INDIVIDUALIZADOS PARA {p.get('nome')} / {diag_completo.upper()}:
[Gere mínimo 14 itens numerados, individualizados com horários específicos]

RESULTADOS ESPERADOS (NOC): {nc['noc']}

Enfermeiro(a): _________________________ COREN: _________"""


def _gerar_ia(tipo, p):
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key: return None

    sedado = any(x in p.get('queixas','').upper() for x in ['SEDADO','SEDADA','IOT','INTUBADO','INTUBADA','VM ','INCONSCIENTE'])
    ctx = "ATENÇÃO: Paciente sedado/intubado. Não use diagnósticos com relato verbal. Use dados objetivos." if sedado else ""

    diag_medico   = p.get('diagnostico', '')
    cid_codigo    = p.get('cid_codigo', '')
    diag_completo = f"{diag_medico}{' ('+cid_codigo+')' if cid_codigo else ''}".strip()
    dispositivos       = p.get('dispositivos', '')
    pendencias         = p.get('pendencias', '')
    nanda_selecionados = p.get('nanda_selecionados', '')

    # Mapeamento clínico — garante NANDA e plano específicos por patologia
    nc = _mapear_nanda_por_patologia(diag_completo)
    # Se o enfermeiro já selecionou diagnósticos manualmente, priorizar
    if nanda_selecionados:
        nc['nanda1'] = nanda_selecionados.split('\n')[0] if nanda_selecionados else nc['nanda1']
        nc['nanda_manual'] = nanda_selecionados

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

        'prescricao': _montar_prompt_prescricao(p, diag_completo, nc, ctx, dispositivos, pendencias, nanda_selecionados),

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


# ────────────────────────────────────────────────────────────
# MÓDULO DIAGNÓSTICO DE ENFERMAGEM — NANDA-I 2024-2026
# ────────────────────────────────────────────────────────────

@app.route('/api/nanda/sugerir', methods=['POST'])
@jwt_required()
def nanda_sugerir():
    """
    Retorna diagnósticos NANDA sugeridos com base no CID-10 e diagnóstico médico.
    Individualizado por paciente — nunca retorna lista fixa genérica.
    """
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    data = request.json or {}
    diagnostico = data.get('diagnostico', '')
    cid_codigo  = data.get('cid_codigo', '')
    queixas     = data.get('queixas', '')
    dispositivos= data.get('dispositivos', '')
    diag_completo = f"{diagnostico} {cid_codigo}".strip()

    nc = _mapear_nanda_por_patologia(diag_completo)
    diags = nc.get('diagnosticos_completos', [])

    # Se não encontrou pelo banco, monta lista do default
    if not diags:
        diags = [
            {'codigo':'00132','nome':'Dor aguda','dominio':'12 — Conforto','classe':'1 — Conforto físico',
             'relacionado':'processo patológico atual','evidenciado':'relato de dor, fácies de dor'},
            {'codigo':'00004','nome':'Risco de infecção','dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
             'relacionado':'procedimentos invasivos e doença de base','evidenciado':'dispositivos invasivos, imunossupressão'},
            {'codigo':'00146','nome':'Ansiedade','dominio':'9 — Enfrentamento','classe':'2 — Respostas de enfrentamento',
             'relacionado':'ameaça ao estado de saúde','evidenciado':'expressão de preocupação, agitação'},
            {'codigo':'00126','nome':'Deficiência de conhecimento','dominio':'5 — Percepção/Cognição','classe':'4 — Cognição',
             'relacionado':'falta de informação sobre doença e tratamento','evidenciado':'perguntas frequentes, comportamento inadequado'},
        ]

    # Adicionar diagnósticos extras baseados em dispositivos
    extras = []
    disp = dispositivos.lower()
    codigos_existentes = [d['codigo'] for d in diags]

    if any(x in disp for x in ['svd','sonda vesical','cateter vesical']):
        if '00016' not in codigos_existentes:
            extras.append({'codigo':'00016','nome':'Eliminação urinária prejudicada',
                'dominio':'3 — Eliminação/Troca','classe':'1 — Função urinária',
                'relacionado':'sonda vesical de demora','evidenciado':'SVD instalada, diurese monitorada'})
    if any(x in disp for x in ['tot','tubo orotraqueal','traqueostomia','vm ','ventilação mecânica']):
        if '00031' not in codigos_existentes:
            extras.append({'codigo':'00031','nome':'Limpeza ineficaz das vias aéreas',
                'dominio':'4 — Atividade/Repouso','classe':'4 — Respostas cardiovasculares/pulmonares',
                'relacionado':'via aérea artificial e secreção aumentada','evidenciado':'TOT/traqueostomia, aspiração necessária'})
    if any(x in disp for x in ['avp','picc','cicc','ficc','cateter venoso']):
        if '00004' not in codigos_existentes:
            extras.append({'codigo':'00004','nome':'Risco de infecção',
                'dominio':'11 — Segurança/Proteção','classe':'1 — Infecção',
                'relacionado':'acesso vascular invasivo','evidenciado':'cateter venoso instalado'})
    if any(x in disp for x in ['sonda enteral','sonda gástrica','sne','sng']):
        if '00039' not in codigos_existentes:
            extras.append({'codigo':'00039','nome':'Risco de aspiração',
                'dominio':'11 — Segurança/Proteção','classe':'2 — Lesão física',
                'relacionado':'sonda enteral e refluxo','evidenciado':'SNE/SNG instalada'})

    todos = diags + extras
    patologia = nc.get('patologia_identificada', 'não identificada')

    return jsonify({
        'diagnosticos': todos,
        'patologia_identificada': patologia,
        'plano_sugerido': nc.get('plano', ''),
        'noc_sugerido': nc.get('noc', ''),
        'total': len(todos),
        'fonte': 'NANDA-I 2024-2026'
    })


@app.route('/api/nanda/banco', methods=['GET'])
@jwt_required()
def nanda_banco():
    """Retorna lista completa de diagnósticos NANDA disponíveis para inclusão manual"""
    if not validar_sessao():
        return jsonify({'erro': 'Sessao invalida.', 'sessao_invalida': True}), 401
    # Lista completa NANDA-I 2024-2026 para busca manual
    banco_completo = [
        {'codigo':'00001','nome':'Desobstrução ineficaz das vias aéreas'},
        {'codigo':'00002','nome':'Nutrição desequilibrada: menor que as necessidades'},
        {'codigo':'00003','nome':'Nutrição desequilibrada: maior que as necessidades'},
        {'codigo':'00004','nome':'Risco de infecção'},
        {'codigo':'00007','nome':'Hipertermia'},
        {'codigo':'00008','nome':'Hipotermia'},
        {'codigo':'00011','nome':'Constipação'},
        {'codigo':'00013','nome':'Diarreia'},
        {'codigo':'00014','nome':'Incontinência fecal'},
        {'codigo':'00016','nome':'Eliminação urinária prejudicada'},
        {'codigo':'00019','nome':'Incontinência urinária funcional'},
        {'codigo':'00026','nome':'Excesso de volume de líquidos'},
        {'codigo':'00027','nome':'Déficit de volume de líquidos'},
        {'codigo':'00028','nome':'Risco de volume de líquidos deficiente'},
        {'codigo':'00029','nome':'Débito cardíaco diminuído'},
        {'codigo':'00030','nome':'Troca de gases prejudicada'},
        {'codigo':'00031','nome':'Limpeza ineficaz das vias aéreas'},
        {'codigo':'00032','nome':'Padrão respiratório ineficaz'},
        {'codigo':'00035','nome':'Risco de lesão'},
        {'codigo':'00039','nome':'Risco de aspiração'},
        {'codigo':'00040','nome':'Síndrome do desuso, risco de'},
        {'codigo':'00044','nome':'Integridade tissular prejudicada'},
        {'codigo':'00046','nome':'Integridade da pele prejudicada'},
        {'codigo':'00047','nome':'Risco de integridade da pele prejudicada'},
        {'codigo':'00048','nome':'Desobstrução das vias aéreas ineficaz'},
        {'codigo':'00049','nome':'Capacidade de recuperação intracraniana diminuída'},
        {'codigo':'00051','nome':'Comunicação verbal prejudicada'},
        {'codigo':'00054','nome':'Isolamento social'},
        {'codigo':'00055','nome':'Desempenho de papel ineficaz'},
        {'codigo':'00059','nome':'Disfunção sexual'},
        {'codigo':'00060','nome':'Processos familiares interrompidos'},
        {'codigo':'00062','nome':'Risco de comprometimento de vínculo'},
        {'codigo':'00078','nome':'Gerenciamento ineficaz da saúde'},
        {'codigo':'00079','nome':'Não adesão'},
        {'codigo':'00085','nome':'Mobilidade física prejudicada'},
        {'codigo':'00086','nome':'Mobilidade no leito prejudicada'},
        {'codigo':'00088','nome':'Deambulação prejudicada'},
        {'codigo':'00092','nome':'Intolerância à atividade'},
        {'codigo':'00093','nome':'Fadiga'},
        {'codigo':'00095','nome':'Insônia'},
        {'codigo':'00100','nome':'Manutenção ineficaz da saúde'},
        {'codigo':'00102','nome':'Déficit no autocuidado para alimentação'},
        {'codigo':'00108','nome':'Déficit no autocuidado para banho'},
        {'codigo':'00109','nome':'Déficit no autocuidado para vestir-se'},
        {'codigo':'00110','nome':'Déficit no autocuidado para higiene íntima'},
        {'codigo':'00118','nome':'Imagem corporal perturbada'},
        {'codigo':'00119','nome':'Autoestima cronicamente baixa'},
        {'codigo':'00120','nome':'Autoestima situacionalmente baixa'},
        {'codigo':'00124','nome':'Desesperança'},
        {'codigo':'00125','nome':'Impotência'},
        {'codigo':'00126','nome':'Deficiência de conhecimento'},
        {'codigo':'00128','nome':'Confusão aguda'},
        {'codigo':'00129','nome':'Confusão crônica'},
        {'codigo':'00130','nome':'Processos de pensamento perturbados'},
        {'codigo':'00131','nome':'Memória prejudicada'},
        {'codigo':'00132','nome':'Dor aguda'},
        {'codigo':'00133','nome':'Dor crônica'},
        {'codigo':'00134','nome':'Náusea'},
        {'codigo':'00137','nome':'Luto'},
        {'codigo':'00138','nome':'Risco de violência direcionada a outros'},
        {'codigo':'00140','nome':'Risco de violência autoprovocada'},
        {'codigo':'00146','nome':'Ansiedade'},
        {'codigo':'00147','nome':'Ansiedade ante a morte'},
        {'codigo':'00148','nome':'Medo'},
        {'codigo':'00150','nome':'Risco de suicídio'},
        {'codigo':'00155','nome':'Risco de quedas'},
        {'codigo':'00160','nome':'Disposição para controle aumentado da saúde'},
        {'codigo':'00161','nome':'Disposição para nutrição aumentada'},
        {'codigo':'00168','nome':'Estilo de vida sedentário'},
        {'codigo':'00179','nome':'Nível de glicemia instável'},
        {'codigo':'00193','nome':'Autogerenciamento ineficaz da saúde'},
        {'codigo':'00195','nome':'Risco de desequilíbrio eletrolítico'},
        {'codigo':'00197','nome':'Motilidade gastrointestinal disfuncional'},
        {'codigo':'00200','nome':'Risco de débito cardíaco diminuído'},
        {'codigo':'00201','nome':'Risco de perfusão tissular cerebral ineficaz'},
        {'codigo':'00202','nome':'Risco de perfusão tissular renal ineficaz'},
        {'codigo':'00203','nome':'Risco de perfusão tissular gastrointestinal ineficaz'},
        {'codigo':'00204','nome':'Perfusão tissular periférica ineficaz'},
        {'codigo':'00205','nome':'Risco de choque'},
        {'codigo':'00206','nome':'Risco de sangramento'},
        {'codigo':'00207','nome':'Risco de integridade vascular intravenosa prejudicada'},
        {'codigo':'00208','nome':'Disposição para controle aumentado da saúde'},
        {'codigo':'00213','nome':'Risco de trauma vascular'},
        {'codigo':'00219','nome':'Risco de olho seco'},
        {'codigo':'00220','nome':'Risco de termorregulação ineficaz'},
        {'codigo':'00226','nome':'Risco de perfusão tissular periférica ineficaz'},
        {'codigo':'00228','nome':'Risco de perfusão tissular periférica ineficaz'},
        {'codigo':'00230','nome':'Síndrome da dor crônica'},
        {'codigo':'00253','nome':'Regulação do humor prejudicada'},
        {'codigo':'00255','nome':'Síndrome de abstinência aguda de substâncias'},
        {'codigo':'00291','nome':'Risco de trombose venosa profunda'},
        {'codigo':'00293','nome':'Risco de úlcera por pressão'},
        {'codigo':'00304','nome':'Risco de queda em adultos'},
        {'codigo':'00307','nome':'Risco de lesão por posicionamento perioperatório'},
    ]
    return jsonify(banco_completo)

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
