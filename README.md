# Multi Party Computation appliqué à un réseau IoT
Ce projet a été conduit dans le cadre d'un projet de recherche et de rédaction scientifique du cursus de Master en Sciences Informatiques à l'Université de Mons.

J'ai décidé d'étudier la thématique du Multi Party Computation en évaluant son implémentation et son intégration dans une machine IoT (ESP32 plus précisément). Pour ce faire, j'ai développé ici une application et deux protocoles <i>P<sub>CEPS</sub></i> et <i>P<sub>CEAS</sub></i>.
Ces deux protocoles sont basés sur le partage de secret de Shamir, le <i>Shamir's Secret Sharing</i> et l'évaluation de circuits arithmétiques afin d'assurer le fonctionnement du principe de calcul multipartite des protocoles MPC. <i>P<sub>CEAS</sub></i> propose également une surcouche, grâce à un protocole VSS basé sur le schéma de Feldman, permettant d'assurer l'intégrité des <i>shares</i> de secret déterminés par SSS.

La recherche a été conduite de manière à optimiser les ressources utilisées par de tels protocoles.

# Utilisation
La branche principale de ce repository contient le code permettant de simuler une partie. La branche IoT contient le code python pouvant être flash sur un ESP32 via MicroPython.

## Simulateur
Pour exécuter une simple partie:
```bash
export PARTY_ID=%party_id%
python3 simulator.py
```

Pour exécuter le <i>Master Node</i>
```bash
python3 simulator.py -master
```
Etant donné le fonctionnement de l'application, le <i>Master Node</i> détermine le protocole de sécurité utilisé. Par défaut, il s'agit du protocole <i>P<sub>CEAS</sub></i>. Pour utiliser <i>P<sub>CEPS</sub></i>, il faut le paramètrer manuellement dans le code de [simulator.py](implementation/simulator.py).

Pour exécuter plusieurs parties en parallèle:
```bash
python3 simulator.py
```
Il faut alors paramétrer manuellement les identifiants des différentes parties dans [simulator.py](implementation/simulator.py).

## IoT
Il faut tout d'abord modifier l'identifiant de la partie qui exécutera le code. Il faut également paramétrer la connexion WiFi (SSID, mot de passe, passerelle de sous-réseau), afin que la partie puisse se connecter à un AP. Finalement il faut flash le code en utilisant MicroPython.

# Application
Chaque partie peut être désignée pour participer activement au réseau et partager des secrets, en utilisant soit <i>P<sub>CEPS</sub></i>, soit <i>P<sub>CEAS</sub></i>. Le secret est déterminé aléatoirement.