# Usa a imagem oficial do Python 3.10
FROM python:3.10

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia apenas o arquivo de dependências primeiro (otimiza cache)
COPY requirements.txt .

# Instala as dependências antes de copiar o resto dos arquivos
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Agora copia os demais arquivos do projeto
COPY . .

# Expõe a porta necessária para a aplicação (se for Flask, geralmente 5000)
EXPOSE 5000

# Define o encoding para evitar problemas
ENV PYTHONIOENCODING=utf-8
ENV PYTHONDONTWRITEBYTECODE=1

# Comando para rodar a aplicação
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "main:app"]
