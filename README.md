

> O assistente mais completo de Sistematização da Assistência de Enfermagem do Brasil

[![Deploy](https://img.shields.io/badge/Deploy-Render.com-46E3B7?style=flat-square)](https://saefacil.onrender.com)
[![Stack](https://img.shields.io/badge/Stack-Flask%20%2B%20Python-blue?style=flat-square)](https://flask.palletsprojects.com)
[![IA](https://img.shields.io/badge/IA-Claude%20Sonnet-orange?style=flat-square)](https://anthropic.com)
[![NANDA](https://img.shields.io/badge/NANDA--I-2024--2026-green?style=flat-square)](#)

## 🚀 Acesse agora

**[https://saefacil.onrender.com](https://saefacil.onrender.com)**

Funciona no navegador — sem instalar nada. Compatível com iPhone, Android e computador.

---

## ✨ Funcionalidades

### 📋 Documentação com IA
- **Evolução SOAP** — formato SOAP com terminologia NANDA-I 2024-2026
- **Prescrição de Enfermagem** — cuidados numerados padrão COREN, individualizados por CID-10
- **Passagem de Plantão** — método SBAR estruturado + FAST HUG integrado
- **Diagnósticos NANDA-I** — taxonomia oficial com 121 diagnósticos em 13 domínios

### 🧠 Diagnóstico de Enfermagem Integrado
- Painel para acrescentar diagnóstico NANDA direto na evolução gerada
- Banco com 121 diagnósticos principais NANDA-I 2024-2026
- Inserção automática com relacionado a, evidenciado por, NIC e NOC
- Sugestão automática pelo CID-10 selecionado
- Inclusão manual livre pelo enfermeiro

### 📊 Escores Clínicos (inédito no Brasil)

| Escore | Finalidade |
|--------|-----------|
| Braden | Risco de úlcera por pressão |
| Glasgow-Pupilar (GCS-P) | Nível de consciência + avaliação pupilar |
| Morse | Risco de quedas |
| Apgar | Avaliação do recém-nascido |
| NEWS 2 | Alerta precoce de deterioração clínica |
| Fugulin | Classificação de dependência de cuidados |

### ⚠️ Alerta Automático de Erros Clínicos
A IA verifica inconsistências antes de salvar:
- SpO2 abaixo de 92%
- Hipotensão ou hipertensão grave
- Taquicardia ou bradicardia significativa
- Febre vs hipotermia
- Dor intensa sem analgesia
- Alergia a medicamento prescrito

### 🧮 Calculadoras Clínicas
- **Dose por peso** (mg/kg → mL)
- **Gotejamento** (macro e microgotas)
- **Diluição de medicamentos**
- **IMC** com classificação
- **Necessidade hídrica diária**

### ⏱️ Modo Plantão
- Cronômetro de turno por paciente
- Checklist de cuidados por paciente
- Atalho para criar SAE direto do checklist

### 🧠 Banco NANDA-I 2024-2026
- 121 diagnósticos com busca por nome, código e sintoma
- Filtros por domínio (13 domínios oficiais NANDA)
- Detalhes completos: definição, fatores relacionados, NIC e NOC
- Sugestão automática baseada no CID-10

### 🎙️ Entrada por Voz
- Fale os dados do paciente e o app transcreve
- Funciona em português brasileiro
- Disponível em Chrome (Android) e Safari (iPhone)

### 📄 PDF Profissional
- Cabeçalho com nome, categoria e COREN
- Linha de assinatura
- Rodapé com data

---

## 💰 Plano

| Plano | Preço | SAEs/mês |
|-------|-------|----------|
| **Pro Mensal** | R$ 67/mês | Ilimitadas |

🔗 **Assine agora:** [pay.hotmart.com/S105507836E](https://pay.hotmart.com/S105507836E)

> Cancele quando quiser, sem fidelidade.

---

## 🛠️ Tecnologias

- **Frontend:** HTML5, CSS3, JavaScript — PWA responsivo
- **Backend:** Python Flask + SQLAlchemy
- **IA:** Anthropic Claude (claude-sonnet-4-6)
- **Deploy:** Render.com
- **Banco de dados:** SQLite (dev) / PostgreSQL (produção)
- **Pagamentos:** Hotmart + Webhook automático

---

## 📁 Estrutura do projeto

```
saefacil/
├── index.html          # Frontend completo (PWA)
├── app.py              # Backend Flask
├── requirements.txt    # Dependências Python
├── Profile             # Configuração Render
├── .python-version     # Python 3.11.x
├── vendas_saefacil.html # Página de vendas
├── termos.html         # Termos de uso
├── privacidade.html    # Política de privacidade
└── Manual_SAEFacil.html # Manual do usuário
```

---

## ⚙️ Variáveis de ambiente (Render)

| Variável | Descrição |
|----------|-----------|
| `SECRET_KEY` | Chave secreta Flask |
| `JWT_SECRET` | Chave JWT |
| `ANTHROPIC_API_KEY` | Chave API Anthropic |
| `DATABASE_URL` | URL PostgreSQL (opcional) |
| `HOTMART_WEBHOOK_TOKEN` | Token webhook Hotmart |

---

## 📱 Instalar como app

**iPhone (Safari):** Compartilhar → Adicionar à Tela de Início

**Android (Chrome):** Menu (⋮) → Adicionar à tela inicial

---

## 👨‍💻 Desenvolvido por

**SPYNET Tecnologia Forense & Soluções Digitais Ltda** · Brasília-DF · 2026

CNPJ: 64.000.808/0001-51

📧 saefacil@gmail.com | 📱 (61) 99512-0797

---

*SAE Fácil — Porque seu tempo no plantão é precioso demais para burocracia.*
