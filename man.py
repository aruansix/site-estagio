import os
import json
import firebase_admin
from firebase_admin import credentials, firestore, initialize_app
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"


firebase_config = json.loads(os.getenv("FIREBASE_CREDENTIALS"))

cred = credentials.Certificate(firebase_config)
initialize_app(cred)

db = firestore.client()
candidatos_ref = db.collection("candidatos")
escritorios_ref = db.collection("escritorios")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Você precisa estar logado para acessar esta página.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    return render_template('index.html', is_logged_in='user_id' in session)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')

       
        candidato_query = candidatos_ref.where("email", "==", email).stream()
        candidato = next(candidato_query, None)
        if candidato and check_password_hash(candidato.get('senha'), senha):
            session['user_id'] = candidato.id
            return redirect(url_for('candidato_dashboard', candidato_id=candidato.id))


        escritorio_query = escritorios_ref.where("email", "==", email).stream()
        escritorio = next(escritorio_query, None)
        if escritorio and check_password_hash(escritorio.get('senha'), senha):
            session['user_id'] = escritorio.id
            return redirect(url_for('contratante_dashboard', escritorio_id=escritorio.id))

        flash("Usuário ou senha incorretos!", "danger")
    return render_template('login.html')


@app.route('/inscricao_candidato', methods=['GET', 'POST'])
def inscricao_candidato():
    if request.method == 'POST':
        dados = request.form.to_dict()
        dados['senha'] = generate_password_hash(dados['senha'])
        candidatos_ref.document().set(dados)
        flash("Cadastro realizado! Faça login.", "success")
        return redirect(url_for('home'))
    return render_template('inscricao_candidato.html')


@app.route('/inscricao_contratante', methods=['GET', 'POST'])
def inscricao_contratante():
    if request.method == 'POST':
        dados = request.form.to_dict()
        dados['senha'] = generate_password_hash(dados['senha'])
        escritorios_ref.document().set(dados)
        flash("Cadastro realizado! Faça login.", "success")
        return redirect(url_for('home'))
    return render_template('inscricao_contratante.html')


@app.route('/candidato_dashboard/<candidato_id>')
@login_required
def candidato_dashboard(candidato_id):
    candidato = candidatos_ref.document(candidato_id).get().to_dict()
    escritorios = [{"id": doc.id, **doc.to_dict()} for doc in escritorios_ref.stream()]

    if 'interesses' not in candidato:
        candidato['interesses'] = []

    return render_template('candidato_dashboard.html', candidato=candidato, escritorios=escritorios)


@app.route('/contratante_dashboard/<escritorio_id>')
@login_required
def contratante_dashboard(escritorio_id):
    escritorio = escritorios_ref.document(escritorio_id).get().to_dict()
    candidatos = []
    candidatos_interessados = []

    for doc in candidatos_ref.stream():
        candidato = doc.to_dict()
        candidato['id'] = doc.id

        if 'interesses' in candidato and escritorio_id in candidato['interesses']:
            candidatos_interessados.append(candidato)
        else:
            candidatos.append(candidato)

    return render_template('contratante_dashboard.html', 
                           escritorio=escritorio, 
                           candidatos_interessados=candidatos_interessados,
                           candidatos=candidatos)


@app.route('/marcar_interesse', methods=['POST'])
@login_required
def marcar_interesse():
    data = request.json
    candidato_id = session['user_id']
    escritorio_id = data.get('escritorio_id')

    if not escritorio_id:
        return jsonify({"sucesso": False, "mensagem": "Escritório inválido"}), 400

    candidato_ref = candidatos_ref.document(candidato_id)
    candidato_doc = candidato_ref.get()

    if not candidato_doc.exists:
        return jsonify({"sucesso": False, "mensagem": "Candidato não encontrado"}), 404

    candidato_data = candidato_doc.to_dict()
    interesses = candidato_data.get("interesses", [])

    if len(interesses) >= 3:
        return jsonify({"sucesso": False, "mensagem": "Você só pode demonstrar interesse em até 3 escritórios."}), 400

    if escritorio_id in interesses:
        return jsonify({"sucesso": False, "mensagem": "Você já demonstrou interesse neste escritório."}), 400

    candidato_ref.update({"interesses": firestore.ArrayUnion([escritorio_id])})

    return jsonify({"sucesso": True, "mensagem": "Interesse marcado com sucesso!"})


@app.route('/remover_interesse', methods=['POST'])
@login_required
def remover_interesse():
    data = request.json
    candidato_id = session['user_id']
    escritorio_id = data.get('escritorio_id')

    if not escritorio_id:
        return jsonify({"sucesso": False, "mensagem": "Escritório inválido"}), 400

    candidato_ref = candidatos_ref.document(candidato_id)
    candidato_doc = candidato_ref.get()

    if not candidato_doc.exists:
        return jsonify({"sucesso": False, "mensagem": "Candidato não encontrado"}), 404

    candidato_data = candidato_doc.to_dict()
    interesses = candidato_data.get("interesses", [])

    if escritorio_id not in interesses:
        return jsonify({"sucesso": False, "mensagem": "Você não demonstrou interesse neste escritório."}), 400

    candidato_ref.update({"interesses": firestore.ArrayRemove([escritorio_id])})

    return jsonify({"sucesso": True, "mensagem": "Interesse removido com sucesso!"})


@app.route('/editar_escritorio/<escritorio_id>', methods=['GET', 'POST'])
@login_required
def editar_escritorio(escritorio_id):
    if session['user_id'] != escritorio_id:
        flash("Você não tem permissão para editar esse escritório.", "danger")
        return redirect(url_for('contratante_dashboard', escritorio_id=session['user_id']))
    
    escritorio_ref = escritorios_ref.document(escritorio_id)
    escritorio = escritorio_ref.get().to_dict()

    if not escritorio:
        flash("Escritório não encontrado!", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        dados_atualizados = request.form.to_dict()

        if 'senha' in dados_atualizados and dados_atualizados['senha']:
            dados_atualizados['senha'] = generate_password_hash(dados_atualizados['senha'])
        else:
            del dados_atualizados['senha']

        escritorio_ref.update(dados_atualizados)
        flash("Cadastro atualizado com sucesso!", "success")
        return redirect(url_for('contratante_dashboard', escritorio_id=escritorio_id))

    return render_template('editar_escritorio.html', escritorio=escritorio)


@app.route('/excluir_escritorio/<escritorio_id>', methods=['POST'])
@login_required
def excluir_escritorio(escritorio_id):
    if session['user_id'] != escritorio_id:
        flash("Você não tem permissão para excluir este escritório.", "danger")
        return redirect(url_for('contratante_dashboard', escritorio_id=session['user_id']))

    escritorio_ref = escritorios_ref.document(escritorio_id)
    escritorio = escritorio_ref.get()

    if not escritorio.exists:
        return jsonify({"sucesso": False, "mensagem": "Escritório não encontrado!"}), 404

    escritorio_ref.delete()


    candidatos = candidatos_ref.stream()
    for candidato in candidatos:
        candidato_data = candidato.to_dict()
        if "interesses" in candidato_data and escritorio_id in candidato_data["interesses"]:
            candidatos_ref.document(candidato.id).update({
                "interesses": firestore.ArrayRemove([escritorio_id])
            })

    session.pop('user_id', None)
    return jsonify({"sucesso": True, "mensagem": "Cadastro excluído com sucesso!"})


@app.route('/editar_candidato/<candidato_id>', methods=['GET', 'POST'])
@login_required
def editar_candidato(candidato_id):
    if session['user_id'] != candidato_id:
        flash("Você não tem permissão para editar este candidato.", "danger")
        return redirect(url_for('candidato_dashboard', candidato_id=session['user_id']))

    candidato_ref = candidatos_ref.document(candidato_id)
    candidato = candidato_ref.get().to_dict()

    if not candidato:
        flash("Candidato não encontrado!", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        dados_atualizados = request.form.to_dict()

        if 'senha' in dados_atualizados and dados_atualizados['senha']:
            dados_atualizados['senha'] = generate_password_hash(dados_atualizados['senha'])
        else:
            del dados_atualizados['senha']

        candidato_ref.update(dados_atualizados)
        flash("Cadastro atualizado com sucesso!", "success")
        return redirect(url_for('candidato_dashboard', candidato_id=candidato_id))

    return render_template('editar_candidato.html', candidato=candidato)


@app.route('/excluir_candidato/<candidato_id>', methods=['POST'])
@login_required
def excluir_candidato(candidato_id):
    if session['user_id'] != candidato_id:
        flash("Você não tem permissão para excluir este candidato.", "danger")
        return redirect(url_for('candidato_dashboard', candidato_id=session['user_id']))

    candidato_ref = candidatos_ref.document(candidato_id)
    candidato = candidato_ref.get()

    if not candidato.exists:
        return jsonify({"sucesso": False, "mensagem": "Candidato não encontrado!"}), 404


    candidato_ref.delete()


    session.pop('user_id', None)
    return jsonify({"sucesso": True, "mensagem": "Cadastro excluído com sucesso!"})


@app.route('/recuperar_senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        nome = request.form.get('nome')


        usuario = get_user_by_email(email)
        if usuario and usuario['nome'] == nome:

            return redirect(url_for('redefinir_senha', email=email))
        else:
            flash("E-mail ou nome incorretos.", "danger")
    return render_template('recuperar_senha.html')


@app.route('/redefinir_senha', methods=['GET', 'POST'])
def redefinir_senha():
    if request.method == 'POST':

        email = request.form.get('email')
        nova_senha = request.form.get('nova_senha')


        if update_user_password(email, nova_senha):
            flash("Senha redefinida com sucesso!", "success")
            return redirect(url_for('login'))
        else:
            flash("Erro ao redefinir a senha.", "danger")
            return redirect(url_for('recuperar_senha'))


    email = request.args.get('email')
    if not email:
        flash("E-mail não fornecido.", "danger")
        return redirect(url_for('recuperar_senha'))

    return render_template('redefinir_senha.html', email=email)


def get_user_by_email(email):
    
    candidato_query = candidatos_ref.where("email", "==", email).stream()
    candidato = next(candidato_query, None)
    if candidato:
        return {"email": email, "nome": candidato.get("nome"), "tipo": "candidato"}


    escritorio_query = escritorios_ref.where("email", "==", email).stream()
    escritorio = next(escritorio_query, None)
    if escritorio:
        return {"email": email, "nome": escritorio.get("nome"), "tipo": "escritorio"}

    return None

def update_user_password(email, nova_senha):
 
    candidato_query = candidatos_ref.where("email", "==", email).stream()
    candidato = next(candidato_query, None)
    if candidato:
        candidatos_ref.document(candidato.id).update({"senha": generate_password_hash(nova_senha)})
        return True

    escritorio_query = escritorios_ref.where("email", "==", email).stream()
    escritorio = next(escritorio_query, None)
    if escritorio:
        escritorios_ref.document(escritorio.id).update({"senha": generate_password_hash(nova_senha)})
        return True

    return False


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Você foi desconectado.", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)