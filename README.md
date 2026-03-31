# 🤖 Guardian AI

Sistema inteligente de **Code Review automático para Pull Requests**, construído com **FastAPI, OpenAI, LangChain e GitHub Checks API**.

O Guardian AI analisa Pull Requests automaticamente e publica:

- ✅ Feedback de Clean Code
- 🧱 Análise de princípios SOLID
- 🔒 Detecção de vulnerabilidades
- 🔧 Sugestões de refatoração
- 💬 Comentários inline diretamente no código
- 📊 Score automático no GitHub Checks

---

# 🚀 Funcionalidades

## ✅ Review automático de Pull Requests
Sempre que um Pull Request é:

- aberto
- atualizado (`synchronize`)
- reaberto

o Guardian AI inicia a análise automaticamente.

---

## 🧼 Análise de Clean Code
Verifica:

- nomes ruins de variáveis e funções
- funções muito grandes
- duplicação de código
- código morto
- comentários desnecessários
- complexidade excessiva

---

## 🧱 Análise SOLID
Valida os 5 princípios:

- **S** → Responsabilidade Única (SRP)
- **O** → Aberto/Fechado (OCP)
- **L** → Substituição de Liskov (LSP)
- **I** → Segregação de Interface (ISP)
- **D** → Inversão de Dependência (DIP)

---

## 🔒 Análise de Segurança
Detecta riscos como:

- SQL Injection
- Command Injection
- uso perigoso de `eval()`
- `shell=True`
- segredos hardcoded
- API keys expostas
- tokens expostos
- falta de validação

---

## 💬 Comentários inline no GitHub
Comenta diretamente nas linhas suspeitas do Pull Request.

Exemplos:

- senha hardcoded
- `eval()`
- SQL inseguro
- `subprocess` perigoso
- uso de tokens no código

---

## 📊 Score automático
Cada PR recebe uma nota de **0 a 10**.

### Faixas
- 🟢 **8–10** → Código saudável
- 🟡 **5–7** → Precisa melhorar
- 🔴 **0–4** → Problemas críticos

---

# ⚙️ Tecnologias

- **FastAPI**
- **PyGithub**
- **OpenAI**
- **LangChain**
- **GitHub Webhooks**
- **GitHub Checks API**
- **asyncio**
- **HMAC SHA256**

---

# 📦 Instalação

```bash
git clone https://github.com/SEU-USUARIO/guardian-ai.git
cd guardian-ai
pip install -r requirements.txt
