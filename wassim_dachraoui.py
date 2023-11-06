from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography import x509
import hashlib
import datetime
import colorama
import cowsay
import getpass
import cryptography

print(colorama.Fore.LIGHTCYAN_EX + "WASSIM.DACHRAOUI/SSIR-N")

def introduire_email():
    global email
    import re
    pattern = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    while True :
        email = input("Entrez votre Email :")
        if re.match(pattern, email):
                return email
        else:
            print("Invalid email")
def introduire_pwd():
    global p
    import string
    while True :
        p = getpass.getpass("Entrez votre Mot de passe : ")
        if len(p)==8:
            if any(car in string.digits for car in p) :
                if any(car in string.ascii_uppercase for car in p) :
                    if any(car in string.ascii_lowercase for car in p) :
                        if any(car in string.punctuation for car in p) :
                            p = hashlib.sha256(p.encode()).hexdigest()
                            return p
                        else :
                            print("au min un cart spécial")
                    else :
                        print("au minimum une lettre miniscule")
                else :
                    print("Au min une lettre maj")
            else :
                print("Au min un numérique")
        else :
            print("long == 8 ")
def enregistrement(nom_utilisateur, mot_de_passe):
    with open('Enregistrement.txt', 'a') as fichier:
        ligne = f"{nom_utilisateur} : {mot_de_passe}\n"
        fichier.write(ligne)
    print(colorama.Fore.RED)
    print("*** Inscription réussie sur votre email.", colorama.Fore.LIGHTWHITE_EX + "(", nom_utilisateur,
          ")")
    print(colorama.Fore.RED)
    cowsay.tux("Bienvenue, " + nom_utilisateur)
    menu()
def authentification(nom_utilisateur, mot_de_passe):
    mot_de_passe = hashlib.sha256(mot_de_passe.encode()).hexdigest()
    with open('Enregistrement.txt', 'r') as fichier:
        lignes = fichier.readlines()
        for ligne in lignes:
            nom, mdp = ligne.strip().split(' : ')
            if nom == nom_utilisateur and mdp == mot_de_passe:
                return True
    return False

#--------- Menu-A (Haché un Mot) ---------
def hache_sh256():
    import hashlib
    print("")
    m = getpass.getpass('Donnez un mot : ')
    mot = hashlib.sha256(m.encode()).hexdigest()
    print('le hashe de (' + m + ') : ' + mot)
    while True:
        try:
            choi1 = input('Voulez-vous hashé une autre mot par sha256 (o/n) :')
            if choi1 == 'o':
                return hache_sh256()
            elif choi1 == 'n':
                return menu_hache()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def hache_salt():
    import bcrypt
    print("")
    m = getpass.getpass('Donnez un mot : ')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(m.encode(), salt)
    print(f"Mot ({m}) haché (bcrypt) : {hashed}")
    while True:
        try:
            choi1 = input('Voulez-vous hashé une autre mot par salt (o/n) :')
            if choi1 == 'o':
                return hache_salt()
            elif choi1 == 'n':
                return menu_hache()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def att_dic ():
    print()
    m = getpass.getpass('Donnez un exemple de mot de passe : ')
    mm = hashlib.sha256(m.encode()).hexdigest()
    with open('dict.SSIR.txt', mode='r') as dic:
        i=0
        for mot in dic:
            mot = mot.strip()
            mot = hashlib.sha256(mot.encode()).hexdigest()
            if mot == mm:
                print("Mot de passe trouvé")
                i=1
    if i == 0:
        print("le Mot de passe '" + m + "' de hache : " + mm)
        print("n'est pas trouvé")
    while True:
        try:
            choi1 = input('Voulez-vous saisire un autre exemple de mot de passe ? (o/n) :')
            if choi1 == 'o':
                return att_dic()
            elif choi1 == 'n':
                return menu_hache()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")


#--------- Menu-B (Chiffrement (RSA))  ---------
def rsa_key ():
    # Génération d'une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Sérialisation de la clé privée au format PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Enregistrement de la clé privée dans un fichier texte
    with open("private_key.txt", "wb") as private_key_file:
        private_key_file.write(private_key_pem)

    # Sérialisation de la clé publique au format PEM
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Enregistrement de la clé publique dans un fichier texte
    with open("public_key.txt", "wb") as public_key_file:
        public_key_file.write(public_key_pem)

    print(" Les paires de clés générées et enregistrées dans des fichiers texte.")
    print("")
    menu_chiffrement_RSA()
def chiffrement_rsa():
    # Charger la clé publique depuis un fichier texte
    with open("public_key.txt", "rb") as public_key_file:
        public_key_pem = public_key_file.read()
        public_key = serialization.load_pem_public_key(public_key_pem)

    # Saisir le mot à chiffrer depuis l'utilisateur
    mot_a_chiffrer = input("Entrez le message à chiffrer : ")

    # Convertir le mot en bytes (UTF-8 est utilisé ici)
    message = mot_a_chiffrer.encode('utf-8')

    # Chiffrement du message avec la clé publique
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    msg_chifree = 'msg_chifree.txt'
    with open(msg_chifree, 'wb') as msg_chifree:
        msg_chifree.write(ciphertext)

    # Afficher le message chiffré
    print("Message chiffré :")
    print(ciphertext)
    print("")
    menu_chiffrement_RSA()
def dechiffrement_rsa():
    # Charger la clé privée depuis un fichier PEM
    with open("private_key.txt", "rb") as private_key_file:
        private_key_pem = private_key_file.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    with open('msg_chifree.txt', 'rb') as file:
        message_chiffre = file.read()

    # Déchiffrer le message
    decrypted_message = private_key.decrypt(
        message_chiffre,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Afficher le message déchiffré
    print("Le Message est : ", decrypted_message.decode('utf-8'))
    print("")
    menu_chiffrement_RSA()
def msg_signe():
    # Chargez la clé privée depuis le fichier
    with open('private_key.txt', 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,  # Si votre clé est protégée par un mot de passe, spécifiez-le ici
            backend=default_backend()
        )

    # Demandez à l'utilisateur d'entrer le message à signer
    message = input("Entrez le message à signer: ").encode('utf-8')

    # Signez le message
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Enregistrez la signature dans un fichier texte
    signature_file = 'signature.txt'
    with open(signature_file, 'wb') as signature_file:
        signature_file.write(signature)

    print("La Signature de votre message est enregistrée dans signature.txt")
    print(signature)
    print("")
    menu_chiffrement_RSA()
def verif_signature():
    # Chargez la clé publique depuis le fichier
    with open('public_key.txt', 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # Le message à vérifier

    message = input("Entrez le message pour verifier la signature: ").encode('utf-8')

    # Lisez la signature à partir du fichier texte
    with open('signature.txt', 'rb') as signature_file:
        signature = signature_file.read()

    try:
        # Essayez de vérifier la signature
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("La signature est valide.")
    except cryptography.exceptions.InvalidSignature:
        print("La signature n'est pas valide.")
    print("")
    menu_chiffrement_RSA()


#--------- Menu-C (Certificat (RSA)) ---------
def cert_key():
    # Générer une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Exporter la clé privée au format PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Exporter la clé publique au format PEM
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Enregistrez les clés dans des fichiers
    with open("cert_private_key.txt", "wb") as private_key_file:
        private_key_file.write(private_pem)

    with open("cert_public_key.txt", "wb") as public_key_file:
        public_key_file.write(public_pem)

    print("Les paire de clés générée avec succès.")
    print("")
    certificat_rsa()
# Créer un certificat auto-signé
def certifecat():
    # Charger la clé privée depuis un fichier texte au format PEM
    private_key_file = 'cert_private_key.txt'
    with open(private_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Créer un certificat auto-signé
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)  # Auto-signé
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

    cert = builder.sign(private_key, hashes.SHA256(), default_backend())

    # Sauvegarder le certificat dans un fichier texte
    certificate_file = 'certificate.txt'
    with open(certificate_file, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

    print("Le certificat générée avec succès et sauvegardée dans certificate.txt.")
    print("")
    certificat_rsa()
def cert_chiffrement():
    # Chargez la clé privée depuis un fichier texte
    with open('cert_private_key.txt', 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,  # Si votre clé est protégée par un mot de passe, spécifiez-le ici
            backend=default_backend()
        )

    # Chargez le certificat depuis un fichier texte
    with open('certificate.txt', 'rb') as cert_file:
        certificate = cert_file.read()

    message = input("Entrez un message pour chiffrer par le certificat: ").encode('utf-8')

    # Chiffrez le message avec le certificat
    ciphertext = private_key.public_key().encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("le Message chiffré ")
    print(ciphertext)
    print("")
    certificat_rsa()


#--------- Les Menus ---------
def accueil():
    print(colorama.Fore.LIGHTGREEN_EX)
    print("*********************")
    print('     Accueil')
    print("*********************")
    print("1-Enregistrement")
    print("2-Authentification")
    print("Q-Quitter")
    print("_____________________")
    while True:
        try:
            choix = input('Donnez votre choix : ')
            if choix == '1':
                nouveau_nom_utilisateur = introduire_email()
                nouveau_mot_de_passe = introduire_pwd()
                enregistrement(nouveau_nom_utilisateur, nouveau_mot_de_passe)
                break
            elif choix == '2':
                nom_utilisateur = introduire_email()
                mot_de_passe = getpass.getpass("Entrez votre mot de passe : ")
                print("")
                if authentification(nom_utilisateur, mot_de_passe):
                    print(colorama.Fore.LIGHTGREEN_EX)
                    print("Authentification réussie. Bienvenue "+nom_utilisateur)
                    print(colorama.Fore.RED)
                    menu()
                else:
                    print("Authentification échouée. Email ou mot de passe incorrect...")
                    accueil()
                break
            elif choix == 'Q':
                quit()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def menu():
    print("*********************")
    print('  Menu Principal')
    print("*********************")
    print("A-Haché un mot")
    print("B-Chiffrement (RSA)")
    print("C-Certificat (RSA)")
    print("Q-Quitter")
    print("_____________________")
    while True:
        try:
            choix = input('Donnez votre choix : ')
            print("")
            if choix == 'A':
                menu_hache()
                break
            elif choix == 'B':
                menu_chiffrement_RSA()
                break
            elif choix == 'C':
                certificat_rsa()
                break
            elif choix == 'Q':
                quit()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def menu_hache():
    print("*********************")
    print('  A-Haché un mot')
    print("*********************")
    print("a-Hacher le mot par SHA256")
    print("b-Hacher le mot en générant un salt")
    print("c-Attaque par dictionnaire")
    print("d-Menu Principal")
    print("q-Quitter")
    print("_____________________")
    while True:
        try:
            choix1 = input('Donnez votre choix : ')
            print("")
            if choix1 == 'a':
                hache_sh256()
                break
            elif choix1 == 'b':
                hache_salt()
                break
            elif choix1 == 'c':
                att_dic()
                break
            elif choix1 == 'd':
                menu()
                break
            elif choix1 == 'q':
                quit()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def menu_chiffrement_RSA():
    print("*********************")
    print('  B-Chiffrement (RSA)')
    print("*********************")
    print("a-Générer les paires de clés (clés.txt)")
    print("b-Chiffrer un message par RSA")
    print("c-Déchiffrer le message")
    print("d-signer un message par RSA")
    print("e-Vérifier la signature du message")
    print("f-Menu Principal")
    print("q-Quitter")
    print("_____________________")
    while True:
        try:
            choix2 = input('Donnez votre choix : ')
            print("")
            if choix2 == 'a':
                rsa_key()
                break
            elif choix2 == 'b':
                chiffrement_rsa()
                break
            elif choix2 == 'c':
                dechiffrement_rsa()
                break
            elif choix2 == 'd':
                msg_signe()
                break
            elif choix2 == 'e':
                verif_signature()
                break
            elif choix2 == 'f':
                menu()
                break
            elif choix2 == 'q':
                quit()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")
def certificat_rsa():
    print("*********************")
    print('  C-Certificat (RSA)')
    print("*********************")
    print("a- Générer les paires de clés dans un fichier")
    print("b- Générer un certificat autosigné par RSA")
    print("c- Chiffrer un message de votre choix par ce certificat")
    print("d- Revenir au menu principal")
    print("q- Quitter")
    print("_____________________")
    while True:
        try:
            choix3 = input('Donnez votre choix : ')
            print("")
            if choix3 == 'a':
                cert_key()
                break
            elif choix3 == 'b':
                certifecat()
                break
            elif choix3 == 'c':
                cert_chiffrement()
                break
            elif choix3 == 'd':
                menu()
                break
            elif choix3 == 'q':
                quit()
            else:
                print("Choix invalide.")
        except ValueError:
            print("Erreur de saisie le code :(")


accueil()



