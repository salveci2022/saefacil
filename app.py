"""
SAE Fácil — Backend Flask
IA para Enfermagem | SPYNET Tecnologia
"""
from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import os, hashlib, requests

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'saefacil-2026')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'saefacil-jwt-2026')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///saefacil.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(256), nullable=False)
    categoria = db.Column(db.String(50))
    coren = db.Column(db.String(50))
    plano = db.Column(db.String(20), default='gratuito')
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    saes = db.relationship('SAE', backref='autor', lazy=True)

    def verificar_senha(self, senha):
        return self.senha_hash == hashlib.sha256(senha.encode()).hexdigest()

    def saes_mes(self):
        inicio = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0)
        return SAE.query.filter(SAE.usuario_id == self.id, SAE.criado_em >= inicio).count()

class SAE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    tipo = db.Column(db.String(30))
    paciente = db.Column(db.String(150))
    leito = db.Column(db.String(100))
    diagnostico = db.Column(db.String(200))
    texto_gerado = db.Column(db.Text)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

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
    return jsonify({'token': token, 'nome': u.nome, 'plano': u.plano,
                    'categoria': u.categoria, 'coren': u.coren})

@app.route('/api/gerar-sae', methods=['POST'])
@jwt_required()
def gerar_sae():
    u = Usuario.query.get(int(get_jwt_identity()))
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
    return jsonify({
        'hoje': SAE.query.filter(SAE.usuario_id==uid, db.func.date(SAE.criado_em)==hoje).count(),
        'mes': SAE.query.filter(SAE.usuario_id==uid, SAE.criado_em>=inicio_mes).count(),
        'total': SAE.query.filter_by(usuario_id=uid).count(),
        'plano': u.plano,
        'limite_mes': 10 if u.plano == 'gratuito' else 9999
    })

def _gerar_ia(tipo, p):
    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        return None
    prompts = {
        'evolucao': f"""Você é enfermeiro especialista. Gere EVOLUÇÃO DE ENFERMAGEM formato SOAP para:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico: {p.get('diagnostico')}
Sinais vitais: {p.get('sv')} | Queixas: {p.get('queixas')}
Sistemas avaliados: {', '.join(p.get('sistemas',[]))} | Exames: {p.get('exames')}
Observações: {p.get('obs')}
Gere SOAP completo e profissional padrão COFEN. Inclua data/hora como [DATA] [HORA]. Linha de assinatura ao final.""",

        'prescricao': f"""Você é enfermeiro especialista. Gere PRESCRIÇÃO DE ENFERMAGEM para:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico: {p.get('diagnostico')}
Sinais: {p.get('sv')} | Queixas: {p.get('queixas')} | Obs: {p.get('obs')}
Liste cuidados numerados (01, 02...) padrão COFEN. Linha de assinatura ao final.""",

        'passagem': f"""Você é enfermeiro especialista. Gere PASSAGEM DE PLANTÃO método SBAR para:
Paciente: {p.get('nome')} | Leito: {p.get('leito')} | Diagnóstico: {p.get('diagnostico')}
Sinais: {p.get('sv')} | Situação: {p.get('queixas')} | Exames: {p.get('exames')}
Estruture S-B-A-R completo, objetivo e claro. Linha de assinatura ao final.""",

        'nanda': f"""Você é enfermeiro especialista em taxonomia NANDA-I 2024-2026. Analise CUIDADOSAMENTE os dados clínicos abaixo e gere 4 DIAGNÓSTICOS DE ENFERMAGEM baseados EXCLUSIVAMENTE no quadro real do paciente.

DADOS DO PACIENTE:
- Nome/Idade: {p.get('nome')}
- Leito/Setor: {p.get('leito')}
- Diagnóstico médico: {p.get('diagnostico')}
- Sinais vitais: {p.get('sv')}
- Avaliação clínica: {p.get('queixas')}
- Sistemas avaliados: {', '.join(p.get('sistemas',[]))}
- Exames/Procedimentos: {p.get('exames')}
- Alergias/Comorbidades: {p.get('alergias')}
- Observações: {p.get('obs')}

REGRAS OBRIGATÓRIAS:
1. Os diagnósticos DEVEM ser compatíveis com o quadro clínico real descrito acima
2. NÃO gere diagnósticos genéricos que não condizem com os dados informados
3. Se o paciente estiver sedado/intubado, NÃO coloque "dor aguda" como prioritário
4. Analise: nível de consciência, via aérea, hemodinâmica, dispositivos invasivos, pele, eliminações
5. Use APENAS o formato NANDA sem NIC e sem NOC
6. Para cada diagnóstico inclua SOMENTE: nome + código NANDA + domínio + relacionado a + evidenciado por (ou fator de risco se for diagnóstico de risco)

FORMATO DE CADA DIAGNÓSTICO:
DIAGNÓSTICO [N]: [Nome do diagnóstico] (NANDA [código])
Domínio [X] - [Nome] | Classe [X] - [Nome]
Relacionado a: [fator causal baseado nos dados do paciente]
Evidenciado por: [características definidoras observadas nos dados]

Gere exatamente 4 diagnósticos ordenados por prioridade clínica. Linha de assinatura ao final."""
    }
    try:
        r = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01',
                     'content-type': 'application/json'},
            json={'model': 'claude-haiku-4-5-20251001', 'max_tokens': 2000,
                  'messages': [{'role': 'user', 'content': prompts.get(tipo, prompts['evolucao'])}]},
            timeout=30
        )
        return r.json()['content'][0]['text']
    except Exception as e:
        print(f'Erro IA: {e}')
        return None

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(404)
def not_found(e):
    return send_from_directory(app.static_folder, 'index.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
