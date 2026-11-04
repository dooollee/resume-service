"""기술명 별칭 사전: 추출·수정·검색이 같은 표준명을 쓰게 한다."""

import re

_CANONICAL = {
    "JavaScript": ["js", "javascript", "자바스크립트", "ecmascript", "es6"],
    "TypeScript": ["ts", "typescript", "타입스크립트"],
    "React": ["react", "reactjs", "react.js", "리액트"],
    "Next.js": ["next", "nextjs", "next.js", "넥스트"],
    "Vue.js": ["vue", "vuejs", "vue.js", "뷰"],
    "Angular": ["angular", "angularjs", "앵귤러"],
    "Node.js": ["node", "nodejs", "node.js", "노드"],
    "Python": ["python", "py", "python3", "파이썬"],
    "FastAPI": ["fastapi", "패스트api"],
    "Django": ["django", "장고"],
    "Flask": ["flask", "플라스크"],
    "Java": ["java", "자바"],
    "Spring": ["spring", "spring boot", "springboot", "스프링", "스프링부트"],
    "Kotlin": ["kotlin", "코틀린"],
    "Go": ["go", "golang", "고랭"],
    "Rust": ["rust", "러스트"],
    "C": ["c", "c언어"],
    "C++": ["c++", "cpp"],
    "C#": ["c#", "csharp", "씨샵"],
    "Swift": ["swift", "스위프트"],
    "SQL": ["sql"],
    "PostgreSQL": ["postgresql", "postgres", "포스트그레스", "포스트그레스큐엘"],
    "MySQL": ["mysql", "마이에스큐엘"],
    "MongoDB": ["mongodb", "mongo", "몽고디비"],
    "Redis": ["redis", "레디스"],
    "AWS": ["aws", "amazon web services", "아마존웹서비스"],
    "GCP": ["gcp", "google cloud", "구글클라우드"],
    "Azure": ["azure", "애저"],
    "Docker": ["docker", "도커"],
    "Kubernetes": ["kubernetes", "k8s", "쿠버네티스"],
    "Terraform": ["terraform", "테라폼"],
    "Git": ["git", "깃"],
    "Linux": ["linux", "리눅스"],
    "Tailwind CSS": ["tailwind", "tailwindcss", "tailwind css", "테일윈드"],
    "HTML": ["html", "html5"],
    "CSS": ["css", "css3"],
    "Figma": ["figma", "피그마"],
    "TensorFlow": ["tensorflow", "텐서플로"],
    "PyTorch": ["pytorch", "torch", "파이토치"],
}
_ALIASES = {alias: canon for canon, aliases in _CANONICAL.items() for alias in [canon.lower(), *aliases]}


def canonical(name: str) -> str:
    cleaned = re.sub(r"\s+", " ", name).strip()
    return _ALIASES.get(cleaned.lower(), cleaned)
