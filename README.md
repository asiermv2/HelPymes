# HelPymes

Bienvenido a la herramienta de escaneo de vulnerabilidades con MCP Helpymes

Manual de instalación:

git clone https://github.com/asiermv2/HelPymes.git

sudo chmod +x install_universal.sh chat_kal_api.py

Una vez instaladas las dependencias y la correcta ejecucion del programa install_universal.sh siga los siguientes pasos:

Antes de empezar, inicie el servidor

    ./kali_server.py
    
Una vez iniciado (En el puerto 5000 por defecto, asegurese que no esté en uso) puede ejecutar sin problemas el chatbot de esta forma:

En el caso de que desee que el servicio de chatbot sea mediiante Groq ejecute:

    ./chat_kali_api,py 

Si desea que sea mediante Anthropic Claude ejecute:

    ./chat_claude.py
    
Recuerde que para la correcta ejecucion es necesario que guarde sus API TOKEN como variable de entorno en un lugar seguro.
¿Cómo saber donde guardarlo?
Escribe en la terminal

    echo $SHELL

Si te devuelve algo como: /usr/bin/zsh

Entonces ejecuta esto en la terminal
    
    nano ~/.zshrc

En cambio si te devuelve algo como: /bin/bash

Entonces ejecuta esto en la terminal:

    ~/.bashrc

Una vez dentro del archivo ve al final y escribe

    export GROQ_API_KEY="tu_api_key"
    export ANTHROPIC_API_KEY="tu_api_key"
    
Introduciendo el API KEY que obtendras desde la página oficial de cada servicio.

https://console.groq.com/keys

https://console.anthropic.com/settings/keys
    
Las sugerencias siempre son bienvenidas, no olvides de aportar tus ideas o consultar tus dudas en la siguiente direccion -> asiermv2@gmail.com . Que lo disfrutes :) !!

No me hago responsable del uso que se haga de la herramienta, esta herramienta está pensada para su ejecucion en entornos controlados , bajo supervisión y permisos otorgados por el/la dueñ@ del sistema atacado.
