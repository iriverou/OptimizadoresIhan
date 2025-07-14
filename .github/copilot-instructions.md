# Instrucciones para GitHub Copilot

## Variables del Proyecto (Cambiar segun proyecto)

### Lenguaje de Programacion Principal
- **PowerShell 5.1+**: Lenguaje principal de desarrollo
- **Python**: Lenguaje secundario para scripts auxiliares
- **JavaScript**: Para interfaces web (si aplica)

### Tecnologias y Frameworks
- **RAMMap**: Analisis detallado de uso de memoria RAM
- **CoreInfo**: Informacion sobre procesador y nucleos
- **Sysinternals Suite**: Herramientas adicionales de diagnostico
- **Windows APIs**: Integracion con funciones nativas del sistema
- **PowerShell ISE/VS Code**: Entorno de desarrollo

### Objetivo General
Desarrollar sistema de optimizacion de Windows mediante PowerShell que mejore rendimiento del sistema operativo de manera automatizada y segura.

### Objetivo Especifico
- Optimizar procesos y servicios de Windows
- Limpiar archivos temporales y bloatware
- Mejorar gestion de memoria RAM
- Automatizar tareas de mantenimiento
- Proporcionar interfaz interactiva para seleccion de procesos
- Mantener estabilidad y seguridad del sistema

### Convenciones de Nomenclatura Especificas del Proyecto
- **PowerShell**: `PascalCase` para funciones, `$camelCase` para variables
- **Python**: `snake_case` para funciones y variables
- **JavaScript**: `camelCase` para funciones y variables
- **Archivos**: `PascalCase.ps1` (PowerShell), `snake_case.py` (Python)

### Estructura de Archivos del Proyecto
- **Main.ps1**: Coordinador principal
- **Etapa[N].ps1**: Modulos de optimizacion por etapas
- **Utils/**: Funciones auxiliares reutilizables
- **Config/**: Archivos de configuracion
- **Logs/**: Archivos de registro

## Configuracion General

- **Idioma de comunicacion**: Español
- **Estilo de codigo**: Limpio, legible y mantenible
- **Documentacion**: Siempre en español
- **Caracteres especiales**: Completamente prohibidos en codigo
- **Emojis**: Prohibidos en codigo y respuestas

## 1. Busqueda de Referencias Previa (Fetch)

Antes de generar cualquier linea de codigo, SIEMPRE realizar busqueda de referencias:

- Buscar patrones y mejores practicas establecidas
- Verificar documentacion oficial de las tecnologias utilizadas
- Consultar estandares de la industria (Microsoft Engineering Playbook, Google Style Guides)
- Revisar convenciones del proyecto actual
- Asegurar consistencia con codigo existente
- Evitar reinvencion de la rueda
- Garantizar compatibilidad e integracion
- Seguir principios de Clean Code y SOLID

## 2. Formulacion de Instrucciones Claras

### Descomposicion de Tareas
- **Descomponer tareas complejas** en subtareas mas sencillas
- Ser muy especifico al describir la tarea: incluir contexto, ejemplos de entrada/salida y restricciones relevantes
- Evitar redaccion ambigua o imprecisa; usar oraciones cortas y claras
- No mezclar multiples requerimientos en una sola instruccion
- Enfocarse solo en lo solicitado, sin añadir funcionalidades extras

### Especificaciones Tecnicas
- Detallar claramente los requisitos (lenguaje de programacion, librerias, formatos de entrada/salida, restricciones)
- Proporcionar ejemplos concretos de entrada y salida esperada
- Definir casos limite y manejo de errores
- Especificar estandares de rendimiento si aplica

## 3. Validacion y Verificacion del Codigo

### Validacion del Codigo Generado
- **Revisar cuidadosamente** toda solucion propuesta por Copilot
- **No implementar nada sin comprobar** que cumpla los requisitos
- **Verificar funcionalidad, seguridad, legibilidad y mantenibilidad**
- **Evaluar casos limite** y manejo de errores
- **Asegurar coherencia** con el estilo del proyecto

### Herramientas de Verificacion
- **Linters**: Usar analizadores estaticos para detectar errores
- **Pruebas unitarias**: Implementar tests para validar funcionalidad
- **Revision de codigo**: Aplicar mejores practicas de code review
- **Herramientas automaticas**: Utilizar CI/CD para validacion continua

### Juicio Humano y Supervision
- **Copilot puede equivocarse**: Mantener siempre control humano
- **Supervisar y ajustar**: Corregir respuestas para que concuerden con estandares
- **Usar como asistente**: Copilot es una herramienta, no un reemplazo del criterio
- **Evaluar y corregir**: Aplicar conocimiento y experiencia en cada sugerencia

## 4. Principios Fundamentales

### Claridad Sobre Inteligencia (Clean Code)
- Priorizar codigo legible sobre "trucos" inteligentes
- Codigo debe ser autoexplicativo y mantenible
- **MALO**: `x && y?.z || 'default'` (criptico)
- **BUENO**: `if (x && y.z) { return y.z; } else { return 'default'; }`

### KISS (Keep It Simple, Stupid)
- Si la solucion parece compleja, buscar alternativa mas simple
- Evitar sobreingenieria y optimizacion prematura
- Mantener funciones pequeñas y con una sola responsabilidad
- Principio de responsabilidad unica (Single Responsibility Principle)

### DRY (Don't Repeat Yourself)
- Evitar duplicacion de codigo
- Extraer funcionalidad comun en funciones o modulos
- Crear bibliotecas reutilizables cuando sea apropiado
- Mantener consistencia en todo el proyecto

### SOLID Principles
- **S**ingle Responsibility: Una clase/funcion debe tener una sola razon para cambiar
- **O**pen/Closed: Abierto para extension, cerrado para modificacion
- **L**iskov Substitution: Objetos de clases derivadas deben ser sustituibles
- **I**nterface Segregation: Interfaces pequenas y especificas
- **D**ependency Inversion: Depender de abstracciones, no de concreciones

## 5. Estructura del Codigo

### Convenciones de Nomenclatura (basadas en Google Style Guide y PEP 8)
- **Variables/funciones**: Usar convenciones del proyecto (ver Variables del Proyecto)
- **Clases**: `PascalCase` (todas las clases)
- **Constantes**: `MAYUSCULAS_CON_UNDERSCORE`
- **Usar nombres descriptivos y significativos**
- **Evitar abreviaciones ambiguas**

### Restricciones de Caracteres (ASCII only)
NO usar caracteres especiales en:
- Nombres de variables
- Nombres de funciones
- Nombres de clases
- Nombres de archivos
- Claves de objetos
- Usar solo caracteres ASCII estandar (a-z, A-Z, 0-9, _)

### Organizacion del Codigo
- **Funciones maximas 20-30 lineas** (Google: 40 lineas)
- **Seguir principios SOLID**
- **Aplicar principio DRY**
- **Mantener bajo acoplamiento y alta cohesion**
- **Separar logica de presentacion**
- **Agrupar funcionalidades relacionadas**

### Indentacion y Espaciado
- **Python**: 4 espacios (PEP 8)
- **JavaScript**: 2 espacios (Airbnb Style Guide)
- **VS Code**: Tabs (Microsoft Guidelines)
- **Nunca mezclar tabs y espacios**
- **Lineas maximas 80 caracteres** (Google: 80, PEP 8: 79)

## 6. Manejo de Errores

### Gestion Robusta (basada en Microsoft Engineering Playbook)
- **Nunca usar `try/catch` vacios**
- **Siempre registrar/loggear errores**
- **Validar entradas de usuario**
- **Considerar casos edge**
- **Proporcionar mensajes de error claros**
- **Usar excepciones especificas**, no genericas
- **Implementar fallback strategies**

### Jerarquia de Excepciones
- **Derivar de Exception**, no de BaseException
- **Usar nombres descriptivos con sufijo Error**
- **Implementar exception chaining apropiado**
- **Documentar condiciones de error**

### Ejemplo de Buena Practica
```python
import logging

def process_data(data):
    """Procesa datos con manejo robusto de errores."""
    if not data:
        raise ValueError("Los datos no pueden estar vacios")
    
    try:
        result = complex_operation(data)
        return result
    except ConnectionError as e:
        logging.error(f'Error de conexion: {e}')
        raise ProcessingError('Error de conexion durante procesamiento') from e
    except ValidationError as e:
        logging.error(f'Error de validacion: {e}')
        raise ProcessingError('Datos invalidos para procesamiento') from e
    except Exception as e:
        logging.error(f'Error inesperado: {e}')
        raise ProcessingError('Error interno durante procesamiento') from e
```

## 7. Comentarios y Documentacion

### Regla del "Por Que" (Clean Code Principle)
- **Comentar solo lo no obvio**
- **Explicar logica de negocio compleja**
- **Documentar decisiones de diseño**
- **NO describir lo que hace el codigo** (debe ser evidente)
- **Usar comentarios para explicar el contexto**

### Docstrings y JSDoc (Google Style Guide)
- **Python**: Usar docstrings con formato Google
- **JavaScript**: Usar JSDoc para funciones publicas
- **Incluir parametros, tipos de retorno y excepciones**
- **Proporcionar ejemplos de uso cuando sea complejo**

### Formato de Documentacion
```python
def process_user_data(users, filters=None):
    """Procesa datos de usuarios aplicando filtros y transformaciones.
    
    Implementa logica de negocio compleja para filtrado y transformacion
    de datos de usuarios, optimizada para listas medianas (<10K elementos).
    
    Args:
        users (List[Dict]): Lista de usuarios con estructura completa
        filters (Dict, opcional): Filtros a aplicar. Defaults to None.
            - 'active_only': bool - Solo usuarios activos
            - 'min_age': int - Edad minima
            
    Returns:
        List[Dict]: Usuarios procesados y transformados
        
    Raises:
        ValueError: Si users no es una lista valida
        ProcessingError: Si falla el procesamiento
        
    Example:
        >>> users = [{'id': 1, 'active': True, 'age': 25}]
        >>> result = process_user_data(users, {'active_only': True})
        >>> len(result)
        1
    """
    if not isinstance(users, list):
        raise ValueError('El parametro users debe ser una lista')
    
    # Aplicar filtros solo si se especifican
    if filters and filters.get('active_only'):
        users = [u for u in users if u.get('active', False)]
    
    return users
```

## 8. Restricciones de Alcance

### No Exceder la Solicitud
- **Implementar SOLO lo solicitado especificamente**
- **No agregar funcionalidades extras sin consultar**
- **Mantener el codigo simple y directo**
- **Evitar divagaciones y codigo innecesario**

### Granularidad y Claridad
- **Si la solicitud es compleja, sugerir desglose** en partes mas pequeñas
- **Pedir aclaracion ante ambiguedades**
- **Confirmar antes de proceder** con implementaciones complejas
- **Documentar supuestos realizados**

### Principio de Menor Sorpresa
- **Hacer lo que el usuario espera**
- **Evitar comportamientos inesperados**
- **Mantener consistencia con patrones establecidos**
- **Proporcionar feedback claro sobre limitaciones**

## 9. Optimizacion y Rendimiento

### Performance con Contexto (Microsoft Engineering Playbook)
- **No optimizar prematuramente** (Donald Knuth)
- **Optimizar solo en bucles criticos** (10K+ registros)
- **Escribir codigo eficiente sin sacrificar legibilidad**
- **Considerar uso de memoria apropiado**
- **Medir antes de optimizar** (benchmarking)

### Evitar Magic Numbers/Strings
```python
# MAL:
if status == 2:
    handle_active_user()

# BIEN:
STATUS_ACTIVE = 2
if status == STATUS_ACTIVE:
    handle_active_user()
```

### Complejidad Algoritmica
- **Conocer Big O notation** de estructuras de datos
- **Elegir algoritmos apropiados** para el tamaño de datos
- **Considerar trade-offs** entre tiempo y espacio
- **Documentar decisiones de performance**

## 10. Seguridad

### Consideraciones de Seguridad (basadas en Microsoft Security Guidelines)
- **Validar y sanitizar todas las entradas**
- **Evitar inyeccion de codigo** (SQL, XSS, Command Injection)
- **Implementar autenticacion y autorizacion** adecuadas
- **Proteger datos sensibles** (encriptacion, hashing)
- **Considerar implicaciones de seguridad** en funciones que interactuan con entradas de usuario
- **Principio de menor privilegio**
- **Fail securely** (fallar de forma segura)

### Validacion de Entrada
```python
def validate_user_input(user_input):
    """Valida y sanitiza entrada de usuario."""
    if not isinstance(user_input, str):
        raise ValueError("Input debe ser string")
    
    # Sanitizar caracteres peligrosos
    sanitized = re.sub(r'[<>"\']', '', user_input)
    
    # Validar longitud
    if len(sanitized) > 100:
        raise ValueError("Input demasiado largo")
    
    return sanitized
```

## 11. Principios de Diseño

### Modularidad
- **Crear funciones y componentes reutilizables**
- **Separar logica de presentacion**
- **Agrupar funcionalidades relacionadas**
- **Mantener componentes pequenos y especializados**

### Inmutabilidad
- **Cuando sea apropiado, favorecer inmutabilidad de datos**
- **Reducir efectos secundarios**
- **Hacer el codigo mas predecible**

### Separacion de Responsabilidades
- **Una funcion/clase debe tener una sola responsabilidad**
- **Separar capas de la aplicacion** (presentacion, logica, datos)
- **Evitar acoplamiento fuerte** entre componentes

## 12. Integracion con Proyecto

### Respeto por la Linea de Trabajo
- **Considerar contexto del proyecto**
- **Adherirse al estilo de codificacion presente**
- **Mantener consistencia en formato** (indentacion, espaciado)
- **Asegurar integracion facil con codigo existente**

### Compatibilidad
- **Verificar compatibilidad con versiones de librerias/frameworks**
- **Considerar restricciones del entorno de desarrollo**
- **Mantener coherencia con arquitectura existente**

### Principio de Consistencia (PEP 8)
- **Consistency within a project is more important**
- **Consistency within one module or function is the most important**
- **When in doubt, use your best judgment**
- **Look at other examples and decide what looks best**

## Ejemplo Completo de Buena Practica

```python
"""
Modulo de procesamiento de datos de usuarios.
Implementa filtrado y transformacion optimizada para listas medianas.
"""

import logging
from typing import Dict, List, Optional


# Constantes del modulo
ESTADO_ACTIVO = 1
LIMITE_PROCESAMIENTO = 10000
EDAD_MINIMA_DEFAULT = 18


class ProcessingError(Exception):
    """Excepcion para errores de procesamiento de datos."""
    pass


def process_user_data(users: List[Dict], filters: Optional[Dict] = None) -> List[Dict]:
    """Procesa datos de usuarios aplicando filtros y transformaciones.
    
    Implementa logica de negocio compleja para filtrado y transformacion
    de datos de usuarios, optimizada para listas medianas (<10K elementos).
    
    Args:
        users: Lista de usuarios con estructura completa
        filters: Filtros a aplicar. Defaults to None.
            - 'active_only': bool - Solo usuarios activos
            - 'min_age': int - Edad minima
            
    Returns:
        Usuarios procesados y transformados
        
    Raises:
        ValueError: Si users no es una lista valida
        ProcessingError: Si falla el procesamiento
        
    Example:
        >>> users = [{'id': 1, 'active': True, 'age': 25}]
        >>> result = process_user_data(users, {'active_only': True})
        >>> len(result)
        1
    """
    # Validacion de entrada
    if not isinstance(users, list):
        raise ValueError('El parametro users debe ser una lista')

    if users and len(users) > LIMITE_PROCESAMIENTO:
        logging.warning(f'Procesando {len(users)} usuarios, considere paginacion')

    try:
        # Aplicar filtros base
        result = _apply_filters(users, filters or {})
        
        # Transformar datos
        result = _transform_user_data(result)
        
        return result

    except Exception as e:
        logging.error(f'Error procesando datos de usuarios: {e}')
        raise ProcessingError('PROCESAMIENTO_FALLIDO') from e


def _apply_filters(users: List[Dict], filters: Dict) -> List[Dict]:
    """Aplica filtros a la lista de usuarios."""
    filtered_users = users
    
    if filters.get('active_only'):
        filtered_users = [u for u in filtered_users if u.get('estado') == ESTADO_ACTIVO]
    
    if 'min_age' in filters:
        min_age = filters['min_age']
        filtered_users = [u for u in filtered_users if u.get('edad', 0) >= min_age]
    
    return filtered_users


def _transform_user_data(users: List[Dict]) -> List[Dict]:
    """Transforma estructura de datos de usuarios."""
    return [
        {
            'id': user.get('id'),
            'nombre': user.get('nombre'),
            'email': user.get('email'),
            'fecha_ultima_actividad': user.get('ultima_actividad')
        }
        for user in users
    ]
```

## Prohibiciones Absolutas

- Caracteres especiales: `á é í ó ú ñ ¿ ¡`
- Emojis en codigo y respuestas
- Codigo sin contexto o documentacion
- Funciones de 100+ lineas sin justificacion
- Optimizaciones prematuras sin medicion previa
- Codigo que no se integre con el proyecto existente
- Funcionalidades no solicitadas especificamente
- Violacion de principios SOLID establecidos
- Uso de magic numbers/strings sin constantes
- Manejo de errores generico o vacio

## Recordatorio Final

Este archivo debe ser consultado antes de cualquier generacion de codigo. El objetivo es mantener un estandar alto de calidad, legibilidad y mantenibilidad en todo el proyecto, siguiendo las mejores practicas de la industria establecidas por Microsoft Engineering Playbook, Google Style Guides, PEP 8, Airbnb JavaScript Style Guide, y VS Code Coding Guidelines.

### Referencias Utilizadas
- [Microsoft Engineering Playbook](https://microsoft.github.io/code-with-engineering-playbook/)
- [Google Style Guides](https://google.github.io/styleguide/)
- [PEP 8 – Style Guide for Python Code](https://peps.python.org/pep-0008/)
- [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)
- [VS Code Coding Guidelines](https://github.com/microsoft/vscode/wiki/Coding-Guidelines)
- [Clean Code Principles](https://clean-code-developer.com/)
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
