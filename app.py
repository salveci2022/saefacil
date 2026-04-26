"""
SAE Fácil — Backend Flask
IA para Enfermagem | SPYNET Tecnologia
"""
from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import os, hashlib, requests, hmac, json

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'saefacil-2026')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'saefacil-jwt-2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///saefacil.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# ─────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(256), nullable=False)
    categoria = db.Column(db.String(50))
    coren = db.Column(db.String(50))
    plano = db.Column(db.String(20), default='gratuito')
    hotmart_id = db.Column(db.String(100))          # ID da assinatura Hotmart
    plano_expira = db.Column(db.DateTime)            # Data de expiração do plano Pro
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    saes = db.relationship('SAE', backref='autor', lazy=True)

    def verificar_senha(self, senha):
        return self.senha_hash == hashlib.sha256(senha.encode()).hexdigest()

    def saes_mes(self):
        inicio = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
        return SAE.query.filter(SAE.usuario_id == self.id, SAE.criado_em >= inicio).count()

    def plano_ativo(self):
        """Verifica se o plano Pro ainda está ativo"""
        if self.plano == 'gratuito':
            return False
        if self.plano_expira and datetime.utcnow() > self.plano_expira:
            # Plano expirado — rebaixa automaticamente
            self.plano = 'gratuito'
            self.hotmart_id = None
            db.session.commit()
            return False
        return True

class SAE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    tipo = db.Column(db.String(30))
    paciente = db.Column(db.String(150))
    leito = db.Column(db.String(100))
    diagnostico = db.Column(db.String(200))
    texto_gerado = db.Column(db.Text)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

class WebhookLog(db.Model):
    """Registra todos os webhooks recebidos do Hotmart para auditoria"""
    id = db.Column(db.Integer, primary_key=True)
    evento = db.Column(db.String(100))
    email = db.Column(db.String(120))
    hotmart_id = db.Column(db.String(100))
    payload = db.Column(db.Text)
    processado = db.Column(db.Boolean, default=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

# ─────────────────────────────────────────
# AUTENTICAÇÃO
# ─────────────────────────────────────────

@app.route('/api/auth/registro', methods=['POST'])
def registro():
    data = request.json
    if not data.get('email') or not data.get('senha') or not data.get('nome'):
        return jsonify({'erro': 'Dados incompletos'}), 400
    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({'erro': 'E-mail já cadastrado'}), 400
    u = Usuario(
        nome=data['nome'], email=data['email'],
        senha_hash=hashlib.sha256(data['senha'].encode()).hexdigest(),
        categoria=data.get('categoria',''), coren=data.get('coren','')
    )
    db.session.add(u)
    db.session.commit()
    token = create_access_token(identity=str(u.id))
    return jsonify({'token': token, 'nome': u.nome, 'plano': u.plano,
                    'categoria': u.categoria, 'coren': u.coren}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    u = Usuario.query.filter_by(email=data.get('email','')).first()
    if not u or not u.verificar_senha(data.get('senha','')):
        return jsonify({'erro': 'Credenciais inválidas'}), 401
    token = create_access_token(identity=str(u.id))
    # Verifica automaticamente se plano expirou
    u.plano_ativo()
    return jsonify({'token': token, 'nome': u.nome, 'plano': u.plano,
                    'categoria': u.categoria, 'coren': u.coren})

# ─────────────────────────────────────────
# GERAÇÃO SAE
# ─────────────────────────────────────────

@app.route('/api/gerar-sae', methods=['POST'])
@jwt_required()
def gerar_sae():
    u = Usuario.query.get(int(get_jwt_identity()))
    # Verifica plano (considera expiração automática)
    if u.plano == 'gratuito' and u.saes_mes() >= 10:
        return jsonify({'erro': 'Limite atingido', 'limite': True}), 403
    data = request.json
    tipo = data.get('tipo', 'evolucao')
    pac = data.get('paciente', {})
    texto = _gerar_ia(tipo, pac)
    if not texto:
        return jsonify({'erro': 'Erro na IA'}), 500
    sae = SAE(usuario_id=u.id, tipo=tipo, paciente=pac.get('nome',''),
              leito=pac.get('leito',''), diagnostico=pac.get('diagnostico',''),
              texto_gerado=texto)
    db.session.add(sae)
    db.session.commit()
    return jsonify({'texto': texto, 'id': sae.id})

@app.route('/api/saes', methods=['GET'])
@jwt_required()
def listar_saes():
    uid = int(get_jwt_identity())
    saes = SAE.query.filter_by(usuario_id=uid).order_by(SAE.criado_em.desc()).limit(50).all()
    return jsonify([{
        'id': s.id, 'tipo': s.tipo, 'paciente': s.paciente,
        'leito': s.leito, 'diagnostico': s.diagnostico,
        'texto': s.texto_gerado, 'data': s.criado_em.isoformat()
    } for s in saes])

@app.route('/api/stats')
@jwt_required()
def stats():
    uid = int(get_jwt_identity())
    u = Usuario.query.get(uid)
    hoje = datetime.utcnow().date()
    inicio_mes = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
    u.plano_ativo()  # Verifica expiração
    return jsonify({
        'hoje': SAE.query.filter(SAE.usuario_id==uid, db.func.date(SAE.criado_em)==hoje).count(),
        'mes': SAE.query.filter(SAE.usuario_id==uid, SAE.criado_em>=inicio_mes).count(),
        'total': SAE.query.filter_by(usuario_id=uid).count(),
        'plano': u.plano,
        'limite_mes': 10 if u.plano == 'gratuito' else 9999
    })

# ─────────────────────────────────────────
# WEBHOOK HOTMART
# ─────────────────────────────────────────

@app.route('/api/webhook/hotmart', methods=['POST'])
def webhook_hotmart():
    """
    Recebe notificações automáticas do Hotmart.
    Configure no Hotmart > Ferramentas > Webhooks:
    URL: https://saefacil.onrender.com/api/webhook/hotmart
    Eventos: PURCHASE_APPROVED, PURCHASE_CANCELED, PURCHASE_REFUNDED,
             SUBSCRIPTION_CANCELLATION
    """
    HOTMART_TOKEN = os.environ.get('HOTMART_WEBHOOK_TOKEN', '')

    # ── Validação do token do Hotmart ──
    hottok = request.headers.get('X-Hotmart-Webhook-Token', '')
    if HOTMART_TOKEN and hottok != HOTMART_TOKEN:
        print(f'[WEBHOOK] Token inválido recebido: {hottok}')
        return jsonify({'erro': 'Token inválido'}), 401

    try:
        data = request.json or {}
    except Exception:
        return jsonify({'erro': 'Payload inválido'}), 400

    evento = data.get('event', '')
    buyer  = data.get('data', {}).get('buyer', {})
    subs   = data.get('data', {}).get('subscription', {})
    purchase = data.get('data', {}).get('purchase', {})

    email      = buyer.get('email', '').lower().strip()
    hotmart_id = subs.get('subscriber', {}).get('code', '') or purchase.get('transaction', '')

    print(f'[WEBHOOK] Evento: {evento} | Email: {email} | ID: {hotmart_id}')

    # Salva log para auditoria
    log = WebhookLog(
        evento=evento,
        email=email,
        hotmart_id=hotmart_id,
        payload=json.dumps(data, ensure_ascii=False)[:2000]
    )
    db.session.add(log)

    # ── Processar evento ──
    usuario = Usuario.query.filter_by(email=email).first()

    if evento in ('PURCHASE_APPROVED', 'PURCHASE_COMPLETE'):
        # ✅ Compra aprovada → ativa plano Pro
        if usuario:
            usuario.plano = 'pro'
            usuario.hotmart_id = hotmart_id
            # Plano válido por 35 dias (30 + 5 de margem)
            usuario.plano_expira = datetime.utcnow() + timedelta(days=35)
            log.processado = True
            print(f'[WEBHOOK] ✅ Plano PRO ativado para {email}')
        else:
            # Usuário ainda não tem conta — salva pendência no log
            print(f'[WEBHOOK] ⚠️ Usuário {email} não encontrado — compra registrada em log')

    elif evento in ('PURCHASE_CANCELED', 'PURCHASE_REFUNDED',
                    'SUBSCRIPTION_CANCELLATION', 'PURCHASE_CHARGEBACK'):
        # ❌ Cancelamento/reembolso → volta para gratuito
        if usuario:
            usuario.plano = 'gratuito'
            usuario.hotmart_id = None
            usuario.plano_expira = None
            log.processado = True
            print(f'[WEBHOOK] ❌ Plano revertido para GRATUITO: {email}')

    elif evento == 'PURCHASE_DELAYED':
        # ⏳ Pagamento pendente — não altera plano ainda
        print(f'[WEBHOOK] ⏳ Pagamento pendente para {email}')

    db.session.commit()
    return jsonify({'status': 'ok', 'evento': evento}), 200


@app.route('/api/webhook/ativar-manual', methods=['POST'])
@jwt_required()
def ativar_manual():
    """
    Ativa plano Pro manualmente por e-mail.
    Use quando o cliente pagar mas o webhook não processar.
    Apenas você (admin) deve usar essa rota.
    Protegida por JWT + senha admin.
    """
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'salveci2018@gmail.com')
    uid = int(get_jwt_identity())
    admin = Usuario.query.get(uid)
    if admin.email != ADMIN_EMAIL:
        return jsonify({'erro': 'Sem permissão'}), 403

    data = request.json
    email_alvo = data.get('email', '').lower().strip()
    dias = int(data.get('dias', 35))

    u = Usuario.query.filter_by(email=email_alvo).first()
    if not u:
        return jsonify({'erro': f'Usuário {email_alvo} não encontrado'}), 404

    u.plano = 'pro'
    u.plano_expira = datetime.utcnow() + timedelta(days=dias)
    u.hotmart_id = data.get('hotmart_id', 'manual')
    db.session.commit()
    print(f'[MANUAL] ✅ Plano PRO ativado manualmente para {email_alvo} por {dias} dias')
    return jsonify({'ok': True, 'email': email_alvo, 'plano': 'pro',
                    'expira': u.plano_expira.isoformat()})


@app.route('/api/webhook/logs', methods=['GET'])
@jwt_required()
def webhook_logs():
    """Lista os últimos webhooks recebidos — só admin"""
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'salveci2018@gmail.com')
    uid = int(get_jwt_identity())
    admin = Usuario.query.get(uid)
    if admin.email != ADMIN_EMAIL:
        return jsonify({'erro': 'Sem permissão'}), 403
    logs = WebhookLog.query.order_by(WebhookLog.criado_em.desc()).limit(50).all()
    return jsonify([{
        'id': l.id, 'evento': l.evento, 'email': l.email,
        'hotmart_id': l.hotmart_id, 'processado': l.processado,
        'data': l.criado_em.isoformat()
    } for l in logs])

# ─────────────────────────────────────────
# IA — GERAÇÃO DE TEXTO
# ─────────────────────────────────────────

@app.route('/api/auth/atualizar-perfil', methods=['PUT'])
@jwt_required()
def atualizar_perfil():
    uid = int(get_jwt_identity())
    u = Usuario.query.get(uid)
    data = request.json
    if data.get('nome'): u.nome = data['nome']
    if data.get('categoria'): u.categoria = data['categoria']
    if data.get('coren'): u.coren = data['coren']
    db.session.commit()
    return jsonify({'ok': True, 'nome': u.nome, 'categoria': u.categoria, 'coren': u.coren})

@app.route('/api/auth/trocar-senha', methods=['POST'])
@jwt_required()
def trocar_senha():
    uid = int(get_jwt_identity())
    u = Usuario.query.get(uid)
    data = request.json
    if not u.verificar_senha(data.get('senha_atual','')):
        return jsonify({'erro': 'Senha atual incorreta'}), 400
    nova = data.get('senha_nova','')
    if len(nova) < 6:
        return jsonify({'erro': 'Nova senha deve ter mínimo 6 caracteres'}), 400
    u.senha_hash = hashlib.sha256(nova.encode()).hexdigest()
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/auth/recuperar-senha', methods=['POST'])
def recuperar_senha():
    """Envia e-mail com nova senha temporária"""
    import secrets, string
    data = request.json
    email = data.get('email','').lower().strip()
    u = Usuario.query.filter_by(email=email).first()
    # Sempre retorna 200 para não revelar se e-mail existe
    if u:
        nova_senha = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
        u.senha_hash = hashlib.sha256(nova_senha.encode()).hexdigest()
        db.session.commit()
        # Envia e-mail via SMTP se configurado
        _enviar_email_recuperacao(email, u.nome, nova_senha)
        print(f'[SENHA] Nova senha temporária para {email}: {nova_senha}')
    return jsonify({'ok': True})

def _enviar_email_recuperacao(email, nome, nova_senha):
    """Envia e-mail com senha temporária via SMTP"""
    import smtplib
    from email.mime.text import MIMEText
    SMTP_HOST  = os.environ.get('SMTP_HOST', '')
    SMTP_PORT  = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USER  = os.environ.get('SMTP_USER', '')
    SMTP_PASS  = os.environ.get('SMTP_PASS', '')
    if not SMTP_HOST or not SMTP_USER:
        print(f'[EMAIL] SMTP não configurado. Senha para {email}: {nova_senha}')
        return
    try:
        corpo = f"""Olá, {nome}!

Você solicitou a recuperação de senha do SAE Fácil.

Sua nova senha temporária é: {nova_senha}

Acesse o app e troque essa senha imediatamente em Perfil > Trocar senha.

Atenciosamente,
Equipe SAE Fácil
https://saefacil.onrender.com
"""
        msg = MIMEText(corpo, 'plain', 'utf-8')
        msg['Subject'] = '🔑 SAE Fácil — Nova senha temporária'
        msg['From'] = SMTP_USER
        msg['To'] = email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, [email], msg.as_string())
        print(f'[EMAIL] Senha enviada para {email}')
    except Exception as e:
        print(f'[EMAIL] Erro ao enviar: {e}')


    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        return None

    sedado = any(x in p.get('queixas','').upper() for x in [
        'SEDADO','SEDADA','RASS','IOT','INTUBADO','INTUBADA',
        'VM ','VENTILAÇÃO MECÂNICA','INCONSCIENTE','GLASGOW'
    ])
    contexto_critico = f"""
ATENÇÃO CLÍNICA — LEIA ANTES DE GERAR:
- Paciente {'em sedação/intubado(a) — NÃO use diagnósticos que exijam relato verbal (ex: Dor aguda com evidência de relato verbal). Use diagnósticos de risco ou baseados em dados objetivos.' if sedado else 'consciente — avalie queixas subjetivas normalmente.'}
- NUNCA gere plano genérico. Cada item do plano deve ser coerente com o quadro real descrito.
- Se houver dispositivos invasivos (CVC, SVD, IOT, drenos), inclua cuidados específicos para eles.
- Diagnóstico prioritário deve refletir a condição mais grave/instável do momento.
""" if sedado else ""

    prompts = {
        'evolucao': f"""Você é enfermeiro especialista em SAE com domínio avançado em NANDA-I 2024-2026, NIC e NOC. Gere EVOLUÇÃO DE ENFERMAGEM formato SOAP com integração completa NANDA+NIC+NOC.
{contexto_critico}
DADOS DO PACIENTE:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico médico: {p.get('diagnostico')}
Sinais vitais: {p.get('sv')}
Avaliação/Queixas: {p.get('queixas')}
Sistemas avaliados: {', '.join(p.get('sistemas',[]))}
Exames/Procedimentos/Dispositivos: {p.get('exames')}
Alergias/Comorbidades: {p.get('alergias','')}
Observações: {p.get('obs')}

ESTRUTURA OBRIGATÓRIA:

EVOLUÇÃO DE ENFERMAGEM
Data/Hora: [DATA] [HORA]
Paciente: [nome] | Leito: [leito]
Diagnóstico médico: [diagnóstico]

S — SUBJETIVO:
{'Paciente sem condições de comunicação verbal (sedação/rebaixamento de consciência). Dados obtidos por observação direta e monitorização.' if sedado else '[Queixas relatadas pelo paciente em suas próprias palavras. Inclua intensidade, localização, fatores de melhora/piora.]'}

O — OBJETIVO:
Sinais vitais: [todos os valores informados]
Sistemas avaliados: [achados objetivos de cada sistema, incluindo dispositivos invasivos e seus aspectos]

A — AVALIAÇÃO (NANDA-I 2024-2026):
Diagnóstico prioritário: [Nome NANDA] (NANDA [código])
Relacionado a: [fator causal específico e real do caso]
Evidenciado por: [características definidoras objetivas observadas]

P — PLANO (NIC + NOC integrados):
INTERVENÇÕES NIC:
• [NIC código] [Nome da intervenção]: [atividade específica 1]
• [NIC código] [Nome da intervenção]: [atividade específica 2]
[mínimo 6 intervenções NIC específicas ao caso, com atividades detalhadas]

RESULTADOS ESPERADOS NOC:
• [NOC código] [Nome do resultado]: Meta — [descrição mensurável do resultado esperado]
• [NOC código] [Nome do resultado]: Meta — [descrição mensurável]
[mínimo 3 resultados NOC]

REGRAS ABSOLUTAS:
1. Diagnóstico COMPATÍVEL com quadro real. {'Paciente sedado: PROIBIDO diagnóstico com relato verbal.' if sedado else ''}
2. Intervenções NIC com códigos reais e atividades específicas ao caso
3. Resultados NOC mensuráveis e alcançáveis para o quadro
4. Terminologia técnica padrão COFEN
5. Linha de assinatura ao final""",

        'prescricao': f"""Você é enfermeiro especialista em SAE com domínio em NANDA-I 2024-2026, NIC e NOC. Gere PRESCRIÇÃO DE ENFERMAGEM baseada em intervenções NIC para o quadro clínico abaixo.
{contexto_critico}
DADOS DO PACIENTE:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico: {p.get('diagnostico')}
Sinais vitais: {p.get('sv')} | Avaliação: {p.get('queixas')}
Dispositivos/Procedimentos: {p.get('exames')} | Comorbidades: {p.get('alergias','')} | Obs: {p.get('obs')}

ESTRUTURA OBRIGATÓRIA:

PRESCRIÇÃO DE ENFERMAGEM
Data: [DATA] | Turno: [manhã/tarde/noite]
Paciente: [nome] | Leito: [leito]

DIAGNÓSTICO DE ENFERMAGEM PRIORITÁRIO (NANDA):
[Nome] (NANDA [código]) — R/A [fator] E/P [evidência]

INTERVENÇÕES DE ENFERMAGEM (baseadas em NIC):
01. [Cuidado específico ao quadro — com horário se aplicável]
02. [Cuidado específico]
03. [Cuidado específico]
[mínimo 12 itens numerados, específicos ao caso real]

{'CUIDADOS ESPECIAIS COM DISPOSITIVOS INVASIVOS: detalhe todos os cuidados com IOT, CVC, SVD e outros dispositivos presentes' if any(x in p.get('queixas','').upper() for x in ['IOT','CVC','SVD','CATETER','DRENO','SNE']) else ''}

RESULTADOS ESPERADOS (NOC):
• [NOC código] [Nome]: [meta mensurável]
• [NOC código] [Nome]: [meta mensurável]

Padrão COFEN. Linha de assinatura ao final.""",

        'passagem': f"""Você é enfermeiro especialista em SAE. Gere PASSAGEM DE PLANTÃO método SBAR com integração NANDA+NIC.
{contexto_critico}
DADOS:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico: {p.get('diagnostico')}
Sinais vitais: {p.get('sv')} | Situação atual: {p.get('queixas')}
Dispositivos/Exames: {p.get('exames')} | Comorbidades: {p.get('alergias','')} | Obs: {p.get('obs')}

ESTRUTURA SBAR OBRIGATÓRIA:

PASSAGEM DE PLANTÃO — SBAR
Data/Hora: [DATA] [HORA] | Leito: [leito]

S — SITUAÇÃO:
Paciente [nome], [idade se disponível], internado(a) em [leito] com diagnóstico de [diagnóstico]. Situação atual: [resumo objetivo do estado no momento]

B — BACKGROUND (Histórico):
Comorbidades: [lista] | Alergias: [lista]
Dispositivos invasivos em uso: [lista com localização e data de inserção se disponível]
Medicações vasoativas/sedação/analgesia em curso: [se aplicável]
Intercorrências no turno: [eventos relevantes]

A — AVALIAÇÃO CLÍNICA:
Diagnóstico de enfermagem ativo: [Nome NANDA] (NANDA [código])
Condição hemodinâmica: [estável/instável — justificativa com valores reais]
Sistemas em alerta: [sistemas com alteração]
Exames/resultados pendentes: [lista]

R — RECOMENDAÇÃO:
Prioridades para o próximo turno:
• [ação prioritária 1]
• [ação prioritária 2]
• [ação prioritária 3]
Alertas: [sinais de deterioração a monitorar]
Pendências médicas: [condutas aguardadas]

Objetivo e claro. Linha de assinatura ao final.""",

        'nanda': f"""Você é enfermeiro especialista em taxonomia NANDA-I 2024-2026 com domínio clínico avançado em NIC (Nursing Interventions Classification) e NOC (Nursing Outcomes Classification). Gere 4 DIAGNÓSTICOS DE ENFERMAGEM com integração completa NANDA+NIC+NOC.
{contexto_critico}
DADOS DO PACIENTE:
- Nome/Idade: {p.get('nome')}
- Leito/Setor: {p.get('leito')}
- Diagnóstico médico: {p.get('diagnostico')}
- Sinais vitais: {p.get('sv')}
- Avaliação clínica: {p.get('queixas')}
- Sistemas avaliados: {', '.join(p.get('sistemas',[]))}
- Dispositivos/Exames: {p.get('exames')}
- Alergias/Comorbidades: {p.get('alergias','')}
- Observações: {p.get('obs')}

REGRAS ABSOLUTAS:
1. Diagnósticos EXCLUSIVAMENTE compatíveis com os dados reais acima
2. {'PACIENTE SEDADO/INCONSCIENTE: PROIBIDO usar características definidoras de relato verbal. Use dados objetivos e diagnósticos de risco.' if sedado else 'Avalie dados subjetivos e objetivos.'}
3. Hierarquia de prioridade: via aérea > ventilação > hemodinâmica > neurológico > infeccioso > integridade cutânea > conforto
4. Para cada diagnóstico: inclua NIC com atividades específicas E NOC com pontuação alvo
5. Códigos NANDA, NIC e NOC devem ser reais e precisos

FORMATO OBRIGATÓRIO PARA CADA DIAGNÓSTICO:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DIAGNÓSTICO [N] — NANDA-I 2024-2026
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 [Nome exato do diagnóstico] (NANDA [código])
Domínio [X] — [Nome do domínio] | Classe [X] — [Nome da classe]
Relacionado a: [fator etiológico específico do caso]
Evidenciado por: [características definidoras objetivas observadas] OU Fator de risco: [se diagnóstico de risco]

🎯 INTERVENÇÕES NIC:
• [Código NIC] [Nome da intervenção NIC]
  - [Atividade específica 1 para este paciente]
  - [Atividade específica 2 para este paciente]
• [Código NIC] [Nome da intervenção NIC]
  - [Atividade específica]

📊 RESULTADOS NOC:
• [Código NOC] [Nome do resultado NOC]
  Meta: [pontuação alvo 1-5] — [descrição do resultado esperado]
• [Código NOC] [Nome do resultado NOC]
  Meta: [pontuação alvo] — [descrição]

Gere os 4 diagnósticos ordenados por prioridade clínica real. Linha de assinatura ao final."""
    }

    try:
        r = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01',
                     'content-type': 'application/json'},
            json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 3000,
                  'messages': [{'role': 'user', 'content': prompts.get(tipo, prompts['evolucao'])}]},
            timeout=30
        )
        return r.json()['content'][0]['text']
    except Exception as e:
        print(f'Erro IA: {e}')
        return None

# ─────────────────────────────────────────
# ROTAS ESTÁTICAS
# ─────────────────────────────────────────

@app.route('/favicon.ico')
def favicon():
    return ('', 204)

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(404)
def not_found(e):
    return send_from_directory(app.static_folder, 'index.html')

# ─────────────────────────────────────────
# INICIALIZAÇÃO
# ─────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
