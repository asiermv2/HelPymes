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
En distribuciones debian -> /usr/bin/env

Las sugerencias siempre son bienvenidas, no olvides de aportar tus ideas o consultar tus dudas en la siguiente direccion -> asiermv2@gmail.com . Que lo disfrutes :) !!

No me hago responsable del uso que se haga de la herramienta, esta herramienta está pensada para su ejecucion en entornos controlados , bajo supervisión y permisos otorgados por el/la dueñ@ del sistema atacado.
