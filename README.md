# 🩺 SAE Fácil — IA para Enfermagem

> **O assistente mais completo de Sistematização de Assistência de Enfermagem do Brasil**

[![Deploy](https://img.shields.io/badge/Deploy-Render-blue)](https://saefacil.onrender.com)
[![Versão](https://img.shields.io/badge/Versão-4.0-green)](https://saefacil.onrender.com)
[![Plataforma](https://img.shields.io/badge/Plataforma-Web%20%7C%20iOS%20%7C%20Android-orange)](https://saefacil.onrender.com)

---

## 🚀 Acesse agora

**[https://saefacil.onrender.com](https://saefacil.onrender.com)**

Funciona no navegador — sem instalar nada. Compatível com iPhone, Android e computador.

---

## ✨ Funcionalidades

### 📝 Documentação com IA
- **Evolução de Enfermagem** — formato SOAP com terminologia NANDA-I 2024-2026
- **Prescrição de Enfermagem** — cuidados numerados padrão COFEN
- **Passagem de Plantão** — método SBAR estruturado
- **Diagnósticos NANDA-NIC-NOC** — taxonomia oficial com 4-5 diagnósticos

### 🔬 Diagnóstico de Enfermagem Integrado
- Botão para **acrescentar diagnóstico NANDA** direto na evolução gerada
- Banco com os principais diagnósticos NANDA-I 2024-2026
- Inserção automática com relacionado a, evidenciado por, NIC e NOC

### 📊 Escores Clínicos (inédito no Brasil)
| Escore | Finalidade |
|--------|-----------|
| **Braden** | Risco de úlcera por pressão |
| **Glasgow-Pupilas (GCS-P)** | Nível de consciência + avaliação pupilar |
| **Morse** | Risco de quedas |
| **Apgar** | Avaliação do recém-nascido |
| **NEWS 2** | Alerta precoce de deterioração clínica |

### ⚠️ Alerta Automático de Erros Clínicos
A IA verifica inconsistências antes de salvar:
- SpO2 abaixo de 92%
- Hipotensão ou hipertensão grave
- Taquicardia ou bradicardia significativa
- Febre ou hipotermia
- Dor intensa sem analgesia
- Alergia x medicamento prescrito

### 🧮 Calculadoras Clínicas
- **Dose por peso** (mg/kg → mL)
- **Gotejamento** (macro e microequipo)
- **Diluição** de medicamentos
- **IMC** com classificação
- **Necessidade hídrica** diária

### ⏱️ Modo Plantão
- Cronômetro de plantão
- Checklist de cuidados por paciente
- Atalho para criar SAE direto do checklist

### 📚 Banco NANDA-I 2024-2026
- 20+ diagnósticos principais com busca por sintoma
- Filtro por domínio
- Detalhes completos: definição, fatores relacionados, NIC e NOC

### 🎤 Entrada por Voz
- Fala os dados do paciente e o app transcreve
- Funciona em português brasileiro
- Disponível em Chrome (Android) e Safari (iPhone)

### 📄 PDF Profissional
- Cabeçalho com nome, categoria e COREN
- Linha de assinatura
- Rodapé com data

---

## 💰 Planos

| Plano | Preço | SAEs/mês |
|-------|-------|---------|
| **Gratuito** | R$ 0 | 10 |
| **Pro** | R$ 29/mês | Ilimitadas |
| **Equipe** | R$ 197/mês | Ilimitadas (10 usuários) |

---

## 🛠️ Tecnologias

- **Frontend:** HTML5, CSS3, JavaScript — PWA responsivo
- **Backend:** Python Flask + SQLAlchemy
- **IA:** Anthropic Claude (claude-haiku)
- **Deploy:** Render.com
- **Banco de dados:** SQLite (dev) / PostgreSQL (produção)

---

## 📁 Estrutura do projeto

```
saefacil/
├── index.html          ← Frontend completo (PWA)
├── app.py              ← Backend Flask + API IA
├── requirements.txt    ← Dependências Python
├── Procfile            ← Configuração Render
└── .python-version     ← Python 3.11.9
```

---

## ⚙️ Variáveis de ambiente (Render)

| Variável | Descrição |
|----------|-----------|
| `SECRET_KEY` | Chave secreta Flask |
| `JWT_SECRET` | Chave JWT |
| `ANTHROPIC_API_KEY` | Chave API Anthropic |
| `DATABASE_URL` | URL PostgreSQL (opcional) |

---

## 👨‍💻 Desenvolvido por

**SPYNET Tecnologia Forense & Soluções Digitais Ltda**
Brasília-DF · 2026

---

## 📱 Instalar como app

**iPhone (Safari):**
Compartilhar → Adicionar à Tela de Início

**Android (Chrome):**
Menu (⋮) → Adicionar à tela inicial

---

*SAE Fácil — Porque seu tempo no plantão é precioso demais para burocracia.*
