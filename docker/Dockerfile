# Utilisation d'une image légère comme image finale
FROM debian:bullseye-slim

# Répertoire de travail
WORKDIR /app

# Définit le nom de l'exécutable (qui devrait être dans un dossier en dehors du contexte)
ARG EXECUTABLE_NAME=data_builder

# Architecture de la plateforme cible
ARG TARGETPLATFORM
ARG TARGETARCH
ARG BINARY_DIR


# Copie l'exécutable en fonction de l'architecture cible
# Veuillez remplacer `/path/to/external/binaries` par le chemin réel vers les fichiers
COPY ./build/build-artifacts/$TARGETARCH/$EXECUTABLE_NAME /def/$EXECUTABLE_NAME
# Définition du point d'entrée
RUN chmod +x /def/$EXECUTABLE_NAME

CMD ["/def/data_builder"]
