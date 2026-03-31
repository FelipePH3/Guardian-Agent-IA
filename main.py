from fastapi import FastAPI, BackgroundTasks, Body, Request, HTTPException
from github import Github, GithubException                  # PyGithub
import asyncio
import hmac
import hashlib
import os
import re
import logging
from functools import lru_cache
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="Guardian AI", version="3.0.0")

GITHUB_TOKEN    = os.getenv("GITHUB_TOKEN")
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY")
WEBHOOK_SECRET  = os.getenv("WEBHOOK_SECRET")          # ← novo: segredo do webhook

if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN não definido no .env")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY não definido no .env")
if not WEBHOOK_SECRET:
    raise ValueError("WEBHOOK_SECRET não definido no .env")

# ─────────────────────────────────────────────
# SDK OFICIAL — PyGithub
# ─────────────────────────────────────────────
gh = Github(GITHUB_TOKEN)

# ─────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2)

# ─────────────────────────────────────────────
# CACHE em memória (commit_sha → análise)
# ─────────────────────────────────────────────
_analysis_cache: dict[str, str] = {}


# ─────────────────────────────────────────────
# SEGURANÇA — Validação de assinatura HMAC
# ─────────────────────────────────────────────

def verify_webhook_signature(payload_bytes: bytes, signature_header: str) -> bool:
    """
    Valida X-Hub-Signature-256 enviado pelo GitHub.
    Usa hmac.compare_digest para evitar timing attacks.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature_header)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

EXTENSION_LANGUAGE_MAP = {
    ".py":    "Python",
    ".js":    "JavaScript",
    ".ts":    "TypeScript",
    ".tsx":   "TypeScript (React)",
    ".jsx":   "JavaScript (React)",
    ".java":  "Java",
    ".go":    "Go",
    ".rb":    "Ruby",
    ".php":   "PHP",
    ".cs":    "C#",
    ".cpp":   "C++",
    ".c":     "C",
    ".rs":    "Rust",
    ".kt":    "Kotlin",
    ".swift": "Swift",
}


def detect_language(filename: str) -> str:
    for ext, lang in EXTENSION_LANGUAGE_MAP.items():
        if filename.endswith(ext):
            return lang
    return "Unknown"


def clean_diff(diff: str) -> str:
    skip_patterns = [
        "__pycache__", "Binary files", ".pyc",
        "node_modules", ".min.js", ".min.css",
        "package-lock.json", "yarn.lock",
    ]
    lines = diff.split("\n")
    return "\n".join(
        line for line in lines
        if not any(p in line for p in skip_patterns)
    )


def safe_truncate_diff(diff: str, max_chars: int = 12_000) -> str:
    if len(diff) <= max_chars:
        return diff
    return diff[:max_chars] + "\n\n[... diff truncado por tamanho ...]"


def calculate_score(analyses: list[str]) -> int:
    combined = " ".join(analyses).lower()
    deductions = 0.0

    critical = [
        "sql injection", "command injection", "remote code execution", "rce",
        "injeção de sql", "xss", "csrf", "xxe",
        "credencial exposta", "senha hardcoded", "secret hardcoded",
    ]
    high = [
        "vulnerabilidade", "vulnerability", "autenticação ausente",
        "autorização ausente", "dados sensíveis", "sensitive data",
        "hardcoded", "sem validação", "no validation",
    ]
    medium = [
        "god class", "violação srp", "violação ocp", "acoplamento alto",
        "responsabilidade única", "função muito longa", "método muito longo",
        "duplicação", "código morto", "dead code",
    ]

    for t in critical:
        if t in combined:
            deductions += 3.0
    for t in high:
        if t in combined:
            deductions += 1.5
    for t in medium:
        if t in combined:
            deductions += 0.5

    return max(0, min(10, round(10 - deductions)))


def extract_files_and_lines(diff: str) -> list[dict]:
    files = []
    current_file = None
    current_line_number = 0

    for line in diff.split("\n"):
        match = re.match(r"^diff --git a/.+ b/(.+)$", line)
        if match:
            current_file = {"file": match.group(1), "lines": []}
            files.append(current_file)
            current_line_number = 0
            continue

        hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk:
            current_line_number = int(hunk.group(1))
            continue

        if current_file is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current_file["lines"].append({
                "content": line[1:],
                "line_number": current_line_number,
            })
            current_line_number += 1
        elif not line.startswith("-"):
            current_line_number += 1

    return files


SECRET_PATTERNS = [
    (r"password\s*=\s*['\"].+['\"]",                          "Senha hardcoded. Use variáveis de ambiente."),
    (r"secret\s*=\s*['\"].+['\"]",                            "Secret hardcoded. Use variáveis de ambiente."),
    (r"api_key\s*=\s*['\"].+['\"]",                           "API key hardcoded. Use variáveis de ambiente."),
    (r"token\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]",           "Token hardcoded. Use variáveis de ambiente."),
    (r"f['\"].*SELECT.*\{",                                    "Possível SQL Injection via f-string. Use queries parametrizadas."),
    (r"eval\s*\(",                                             "eval() é perigoso. Evite execução dinâmica de código."),
    (r"subprocess\.call\(.+shell=True",                       "shell=True em subprocess é perigoso. Passe lista de argumentos."),
]


def generate_inline_comments(files: list[dict]) -> list[dict]:
    comments = []
    for file in files:
        for entry in file["lines"]:
            for pattern, message in SECRET_PATTERNS:
                if re.search(pattern, entry["content"], re.IGNORECASE):
                    comments.append({
                        "path": file["file"],
                        "line": entry["line_number"],
                        "body": f"⚠️ {message}",
                    })
                    break
    return comments


# ─────────────────────────────────────────────
# GITHUB — PyGithub SDK
# ─────────────────────────────────────────────

def fetch_pr_files(repo_name: str, pr_number: int) -> str:
    """
    Usa PyGithub para buscar todos os arquivos do PR.
    A paginação é tratada automaticamente pelo SDK.
    """
    try:
        repo  = gh.get_repo(repo_name)
        pr    = repo.get_pull(pr_number)
        files = pr.get_files()           # PaginatedList — itera automaticamente

        patches = []
        for f in files:
            filename = f.filename
            patch    = f.patch or ""
            status   = f.status

            if not patch:
                patches.append(f"diff --git a/{filename} b/{filename}\n# [{status}] sem diff de texto")
                continue

            patches.append(f"diff --git a/{filename} b/{filename}\n{patch}")

        return "\n\n".join(patches)

    except GithubException as e:
        logging.error(f"Erro ao buscar arquivos do PR via PyGithub: {e}")
        raise


def post_pr_comment(repo_name: str, pr_number: int, body: str) -> None:
    """Posta comentário geral na thread do PR."""
    try:
        repo = gh.get_repo(repo_name)
        pr   = repo.get_pull(pr_number)
        pr.create_issue_comment(body)
        logging.info(f"Comentário geral postado no PR #{pr_number}")
    except GithubException as e:
        logging.error(f"Erro ao postar comentário geral: {e}")
        raise


def post_inline_comments(
    repo_name: str,
    pr_number: int,
    commit_sha: str,
    comments: list[dict],
) -> None:
    """Posta comentários inline usando a Review API do GitHub."""
    if not comments:
        return
    try:
        repo   = gh.get_repo(repo_name)
        pr     = repo.get_pull(pr_number)
        commit = repo.get_commit(commit_sha)

        # Agrupa todos os comentários numa única revisão (menos ruído na UI)
        pr.create_review(
            commit=commit,
            body="Guardian AI — comentários automáticos de segurança",
            event="COMMENT",
            comments=[
                {
                    "path": c["path"],
                    "line": c["line"],
                    "body": c["body"],
                    "side": "RIGHT",
                }
                for c in comments
            ],
        )
        logging.info(f"{len(comments)} comentário(s) inline postado(s) via Review API")
    except GithubException as e:
        logging.warning(f"Falha ao postar comentários inline: {e}")


def post_check_run(
    repo_name: str,
    commit_sha: str,
    score: int,
    conclusion: str,
    summary: str,
) -> None:
    """
    Cria um GitHub Check Run com o resultado da análise.
    Aparece como status obrigatório na interface do PR.
    """
    try:
        repo = gh.get_repo(repo_name)
        repo.create_check_run(
            name="Guardian AI",
            head_sha=commit_sha,
            status="completed",
            conclusion=conclusion,        # "success" | "neutral" | "failure"
            output={
                "title": f"Score: {score}/10",
                "summary": summary,
            },
        )
        logging.info(f"Check Run criado: conclusion={conclusion}, score={score}")
    except GithubException as e:
        logging.warning(f"Falha ao criar Check Run (token pode não ter permissão checks:write): {e}")


# ─────────────────────────────────────────────
# AI — prompts e chamadas paralelas
# ─────────────────────────────────────────────

SYSTEM_PROMPT = SystemMessage(content="""
Você é um Staff Engineer Sênior realizando um code review crítico e construtivo.

REGRAS OBRIGATÓRIAS:
1. Analise APENAS o código que está no diff (linhas com + são adições)
2. Seja ESPECÍFICO: cite o nome da função/classe/variável real do código
3. NÃO invente problemas que não existem no diff
4. NÃO seja genérico — evite frases sem contexto específico
5. Se não houver problemas na sua área: "✅ Nenhum problema encontrado nesta área."
6. Liste no máximo 5 problemas por seção, ordenados por gravidade

Formato de cada problema:
**[GRAVIDADE] Título curto**
- Onde: `nome_da_função()` / linha X
- Problema: descrição técnica precisa
- Impacto: consequência real
- Solução: código ou instrução direta
""")


def _build_clean_code_msg(diff: str, lang: str) -> HumanMessage:
    return HumanMessage(content=f"""
Analise SOMENTE Clean Code no diff abaixo.
Linguagem(s): {lang}

Verifique:
- Nomes de variáveis/funções/classes expressivos
- Funções com responsabilidade única e tamanho adequado
- Ausência de código duplicado ou morto
- Comentários desnecessários vs. código auto-explicativo
- Complexidade ciclomática excessiva

NÃO mencione segurança ou SOLID.

DIFF:
```
{diff}
```
""")


def _build_solid_msg(diff: str, lang: str) -> HumanMessage:
    return HumanMessage(content=f"""
Analise SOMENTE os princípios SOLID no diff abaixo.
Linguagem(s): {lang}

Verifique cada princípio explicitamente:
- S (SRP): cada classe/função tem uma única responsabilidade?
- O (OCP): aberto para extensão, fechado para modificação?
- L (LSP): subtipos são substituíveis?
- I (ISP): interfaces são específicas?
- D (DIP): dependências apontam para abstrações?

NÃO mencione segurança ou Clean Code.

DIFF:
```
{diff}
```
""")


def _build_security_msg(diff: str, lang: str) -> HumanMessage:
    return HumanMessage(content=f"""
Analise SOMENTE segurança no diff abaixo.
Linguagem(s): {lang}

Verifique:
- Injeção (SQL, comando, LDAP, XPath)
- Autenticação e autorização ausentes ou fracas
- Dados sensíveis expostos (logs, respostas, hardcoded)
- Validação e sanitização de inputs
- Configurações inseguras (CORS, headers, TLS)

NÃO mencione Clean Code ou SOLID.

DIFF:
```
{diff}
```
""")


async def _call_llm(messages: list) -> str:
    """Wrapper async para chamar o LLM síncrono em thread separada."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: llm.invoke(messages).content)


async def analyze_diff(diff: str, languages: list[str]) -> tuple[str, int]:
    """
    Executa as 3 análises em PARALELO com asyncio.gather,
    depois chama a refatoração com os resultados.
    Retorna (markdown_completo, score).
    """
    lang_str = ", ".join(set(languages)) if languages else "Unknown"

    # ── Paralelo: Clean Code + SOLID + Segurança ─────────────────────
    clean_code, solid, security = await asyncio.gather(
        _call_llm([SYSTEM_PROMPT, _build_clean_code_msg(diff, lang_str)]),
        _call_llm([SYSTEM_PROMPT, _build_solid_msg(diff, lang_str)]),
        _call_llm([SYSTEM_PROMPT, _build_security_msg(diff, lang_str)]),
    )

    # ── Sequencial: Refatoração depende dos 3 anteriores ─────────────
    refactor = await _call_llm([
        SYSTEM_PROMPT,
        HumanMessage(content=f"""
Com base nos problemas identificados abaixo, sugira refatoração com código real.

Mostre ANTES e DEPOIS apenas para os problemas mais críticos (máx 3).
Use blocos de código com a linguagem correta.

=== Clean Code ===
{clean_code}

=== SOLID ===
{solid}

=== Segurança ===
{security}
"""),
    ])

    score = calculate_score([clean_code, solid, security])
    emoji = "🟢" if score >= 8 else "🟡" if score >= 5 else "🔴"

    markdown = f"""## 🤖 Guardian AI — Code Review

### {emoji} Score: {score}/10

<details>
<summary>📋 Linguagem(s): {lang_str}</summary>
</details>

---

### 🧼 Clean Code
{clean_code}

---

### 🧱 SOLID
{solid}

---

### 🔒 Segurança
{security}

---

### 🔧 Sugestões de Refatoração
{refactor}

---
*Gerado por [Guardian AI](https://github.com) • Modelo: GPT-4o-mini*
"""
    return markdown, score


# ─────────────────────────────────────────────
# PROCESSAMENTO PRINCIPAL
# ─────────────────────────────────────────────

async def process_pr(payload: dict) -> None:
    try:
        logging.info("▶ Iniciando processamento do PR...")

        pr         = payload["pull_request"]
        repo_name  = payload["repository"]["full_name"]
        pr_number  = pr["number"]
        commit_sha = pr["head"]["sha"]

        logging.info(f"   Repo: {repo_name} | PR: #{pr_number} | Commit: {commit_sha[:8]}")

        # ── 1. Cache — evita reprocessar o mesmo commit ───────────────
        if commit_sha in _analysis_cache:
            logging.info(f"   Cache hit para commit {commit_sha[:8]} — pulando análise")
            return

        # ── 2. Buscar diff via PyGithub ───────────────────────────────
        raw_diff = fetch_pr_files(repo_name, pr_number)
        logging.info(f"   Diff bruto: {len(raw_diff)} chars")

        # ── 3. Limpar e truncar ───────────────────────────────────────
        diff = safe_truncate_diff(clean_diff(raw_diff))
        logging.info(f"   Diff limpo: {len(diff)} chars")

        # ── 4. Detectar linguagens ────────────────────────────────────
        files_parsed = extract_files_and_lines(raw_diff)
        languages    = list({detect_language(f["file"]) for f in files_parsed if f["file"]})
        logging.info(f"   Linguagens: {languages}")

        # ── 5. Análise IA (paralela) ──────────────────────────────────
        analysis_md, score = await analyze_diff(diff, languages)

        # ── 6. Salvar no cache ────────────────────────────────────────
        _analysis_cache[commit_sha] = analysis_md

        # ── 7. Comentário geral na thread do PR ───────────────────────
        post_pr_comment(repo_name, pr_number, analysis_md)

        # ── 8. Comentários inline (secrets / padrões perigosos) ───────
        inline_comments = generate_inline_comments(files_parsed)
        post_inline_comments(repo_name, pr_number, commit_sha, inline_comments)

        # ── 9. GitHub Check Run ───────────────────────────────────────
        conclusion = "success" if score >= 7 else "neutral" if score >= 4 else "failure"
        post_check_run(
            repo_name, commit_sha, score, conclusion,
            summary=f"Guardian AI analisou o PR e atribuiu score {score}/10.",
        )

        logging.info(f"✅ Processamento concluído — score={score}, conclusion={conclusion}")

    except Exception as e:
        logging.error(f"❌ ERRO NO PROCESSAMENTO: {e}", exc_info=True)


# ─────────────────────────────────────────────
# WEBHOOK
# ─────────────────────────────────────────────

@app.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
):
    # ── Lê o body raw para validar a assinatura ───────────────────────
    body = await request.body()

    # ── Validação HMAC ────────────────────────────────────────────────
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_webhook_signature(body, signature):
        logging.warning("Assinatura de webhook inválida — requisição rejeitada")
        raise HTTPException(status_code=401, detail="Assinatura inválida")

    # ── Parse do payload ──────────────────────────────────────────────
    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Payload não é JSON válido")

    action = payload.get("action")
    if action not in ["opened", "synchronize", "reopened"]:
        return {"ignored": True, "action": action}

    if "pull_request" not in payload:
        raise HTTPException(status_code=400, detail="Payload sem pull_request")

    pr_number = payload["pull_request"]["number"]
    repo      = payload["repository"]["full_name"]
    logging.info(f"📥 Webhook validado: {repo} PR #{pr_number} ({action})")

    background_tasks.add_task(process_pr, payload)
    return {"ok": True, "pr": pr_number, "action": action}


@app.get("/health")
async def health():
    return {"status": "ok", "version": "3.0.0"}