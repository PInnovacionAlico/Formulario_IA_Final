/**
 * Sistema de Notificaciones Unificado
 * Para usar en todo el sitio de forma consistente
 */

// Tipos de notificaciones
const NotificationType = {
  SUCCESS: 'success',
  ERROR: 'error',
  WARNING: 'warning',
  INFO: 'info'
};

/**
 * Muestra una notificación toast en la esquina superior derecha
 * @param {string} message - Mensaje a mostrar
 * @param {string} type - Tipo de notificación (success, error, warning, info)
 * @param {number} duration - Duración en milisegundos (default: 4000)
 */
function showNotification(message, type = NotificationType.SUCCESS, duration = 4000) {
  // Remover notificación existente si hay alguna
  const existingNotification = document.getElementById('globalNotification');
  if (existingNotification) {
    existingNotification.remove();
  }

  // Configuración de estilos por tipo
  const typeConfig = {
    success: {
      gradient: 'linear-gradient(135deg, #28a745 0%, #20c997 100%)',
      icon: '✅'
    },
    error: {
      gradient: 'linear-gradient(135deg, #dc3545 0%, #c82333 100%)',
      icon: '❌'
    },
    warning: {
      gradient: 'linear-gradient(135deg, #ffc107 0%, #ff9800 100%)',
      icon: '⚠️'
    },
    info: {
      gradient: 'linear-gradient(135deg, #17a2b8 0%, #138496 100%)',
      icon: 'ℹ️'
    }
  };

  const config = typeConfig[type] || typeConfig.info;

  const notification = document.createElement('div');
  notification.id = 'globalNotification';
  notification.innerHTML = `
    <span style="font-size: 16px; margin-right: 8px;">${config.icon}</span>
    <span>${message}</span>
  `;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${config.gradient};
    color: white;
    padding: 16px 24px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    z-index: 2147483647;
    font-weight: 600;
    font-size: 14px;
    display: flex;
    align-items: center;
    animation: slideInRight 0.3s ease-out;
    max-width: 400px;
  `;

  document.body.appendChild(notification);

  // Remover después de la duración especificada
  setTimeout(() => {
    notification.style.animation = 'slideOutRight 0.3s ease-out';
    setTimeout(() => notification.remove(), 300);
  }, duration);
}

/**
 * Muestra un diálogo de confirmación estilizado
 * @param {string} message - Mensaje de confirmación
 * @param {string} confirmText - Texto del botón de confirmar (default: "Confirmar")
 * @param {string} cancelText - Texto del botón de cancelar (default: "Cancelar")
 * @returns {Promise<boolean>} - True si confirma, false si cancela
 */
function showConfirmDialog(message, confirmText = 'Confirmar', cancelText = 'Cancelar') {
  return new Promise((resolve) => {
    // Remover diálogo existente si hay alguno
    const existingDialog = document.getElementById('globalConfirmDialog');
    if (existingDialog) {
      existingDialog.remove();
    }

    const overlay = document.createElement('div');
    overlay.id = 'globalConfirmDialog';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 10002;
      animation: fadeIn 0.2s ease-out;
    `;

    const dialog = document.createElement('div');
    dialog.style.cssText = `
      background: white;
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      max-width: 450px;
      width: 90%;
      animation: scaleIn 0.3s ease-out;
    `;

    dialog.innerHTML = `
      <div style="margin-bottom: 24px;">
        <div style="font-size: 20px; font-weight: 700; color: #1a1a2e; margin-bottom: 12px;">
          ⚠️ Confirmación
        </div>
        <div style="font-size: 15px; color: #555; line-height: 1.5;">
          ${message}
        </div>
      </div>
      <div style="display: flex; gap: 12px; justify-content: flex-end;">
        <button id="confirmDialogCancel" style="
          padding: 10px 20px;
          border: 2px solid #ddd;
          background: white;
          color: #666;
          border-radius: 8px;
          cursor: pointer;
          font-weight: 600;
          font-size: 14px;
          transition: all 0.2s;
        ">${cancelText}</button>
        <button id="confirmDialogConfirm" style="
          padding: 10px 20px;
          border: none;
          background: linear-gradient(135deg, var(--alico-gold) 0%, var(--alico-gold-80) 100%);
          color: white;
          border-radius: 8px;
          cursor: pointer;
          font-weight: 600;
          font-size: 14px;
          transition: all 0.2s;
        ">${confirmText}</button>
      </div>
    `;

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Event listeners
    document.getElementById('confirmDialogCancel').addEventListener('click', () => {
      overlay.style.animation = 'fadeOut 0.2s ease-out';
      setTimeout(() => {
        overlay.remove();
        resolve(false);
      }, 200);
    });

    document.getElementById('confirmDialogConfirm').addEventListener('click', () => {
      overlay.style.animation = 'fadeOut 0.2s ease-out';
      setTimeout(() => {
        overlay.remove();
        resolve(true);
      }, 200);
    });

    // Cerrar al hacer clic fuera del diálogo
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.style.animation = 'fadeOut 0.2s ease-out';
        setTimeout(() => {
          overlay.remove();
          resolve(false);
        }, 200);
      }
    });
  });
}

/**
 * Muestra un indicador de carga
 * @param {string} message - Mensaje a mostrar (default: "Cargando...")
 * @returns {function} - Función para ocultar el loader
 */
function showLoader(message = 'Cargando...') {
  const existingLoader = document.getElementById('globalLoader');
  if (existingLoader) {
    existingLoader.remove();
  }

  const loader = document.createElement('div');
  loader.id = 'globalLoader';
  loader.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 10003;
    animation: fadeIn 0.2s ease-out;
  `;

  loader.innerHTML = `
    <div style="
      background: white;
      padding: 30px 40px;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      text-align: center;
    ">
      <div style="
        width: 50px;
        height: 50px;
        border: 4px solid var(--alico-gold-20);
        border-top-color: var(--alico-gold);
        border-radius: 50%;
        margin: 0 auto 16px;
        animation: spin 1s linear infinite;
      "></div>
      <div style="
        font-size: 16px;
        font-weight: 600;
        color: #1a1a2e;
      ">${message}</div>
    </div>
  `;

  document.body.appendChild(loader);

  // Retornar función para ocultar el loader
  return function hideLoader() {
    const loaderElement = document.getElementById('globalLoader');
    if (loaderElement) {
      loaderElement.style.animation = 'fadeOut 0.2s ease-out';
      setTimeout(() => loaderElement.remove(), 200);
    }
  };
}

// Agregar animaciones CSS necesarias
function initializeSharedStyles() {
  if (document.getElementById('sharedComponentsStyles')) return;

  const style = document.createElement('style');
  style.id = 'sharedComponentsStyles';
  style.textContent = `
    @keyframes slideInRight {
      from {
        transform: translateX(400px);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
    
    @keyframes slideOutRight {
      from {
        transform: translateX(0);
        opacity: 1;
      }
      to {
        transform: translateX(400px);
        opacity: 0;
      }
    }
    
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    @keyframes fadeOut {
      from { opacity: 1; }
      to { opacity: 0; }
    }
    
    @keyframes scaleIn {
      from {
        transform: scale(0.9);
        opacity: 0;
      }
      to {
        transform: scale(1);
        opacity: 1;
      }
    }
    
    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* Estilos hover para botones de confirmación */
    #confirmDialogCancel:hover {
      background: #f8f9fa !important;
      border-color: #999 !important;
    }
    
    #confirmDialogConfirm:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(219, 149, 0, 0.4);
    }
  `;
  
  document.head.appendChild(style);
}

// Inicializar estilos cuando se carga el script
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeSharedStyles);
} else {
  initializeSharedStyles();
}

/**
 * Muestra un overlay de generación de imagen con mensajes rotativos
 * @returns {function} - Función para ocultar el overlay
 */
function showGeneratingOverlay() {
  const existingOverlay = document.getElementById('generatingOverlay');
  if (existingOverlay) {
    existingOverlay.remove();
  }

  const messages = [
    '🎨 Generando tu diseño personalizado...',
    '✨ La IA está analizando tus preferencias...',
    '🔮 Perfeccionando colores y tipografía...',
    '🎯 Ajustando detalles del empaque...',
    '🚀 Aplicando los últimos toques...',
    '🌟 Casi listo, preparando tu imagen...'
  ];

  let currentMessageIndex = 0;
  let progress = 20;

  const overlay = document.createElement('div');
  overlay.id = 'generatingOverlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.85);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 10005;
    animation: fadeIn 0.3s ease-out;
  `;

  overlay.innerHTML = `
    <div style="
      background: white;
      padding: 50px;
      border-radius: 20px;
      box-shadow: 0 10px 50px rgba(0,0,0,0.5);
      text-align: center;
      max-width: 500px;
      width: 90%;
      animation: scaleIn 0.3s ease-out;
    ">
      <div style="
        width: 80px;
        height: 80px;
        border: 6px solid #f3f3f3;
        border-top: 6px solid var(--alico-gold);
        border-radius: 50%;
        margin: 0 auto 30px;
        animation: spin 1s linear infinite;
      "></div>
      
      <h2 style="
        font-size: 24px;
        font-weight: 700;
        color: #1a1a2e;
        margin-bottom: 20px;
      ">
        Generando tu diseño
      </h2>
      
      <p id="rotatingMessage" style="
        font-size: 16px;
        color: #666;
        line-height: 1.6;
        min-height: 50px;
        transition: opacity 0.3s ease;
      ">
        ${messages[0]}
      </p>
      
      <div style="
        width: 100%;
        height: 6px;
        background: #f0f0f0;
        border-radius: 10px;
        margin-top: 30px;
        overflow: hidden;
      ">
        <div id="generatingProgressBar" style="
          width: 20%;
          height: 100%;
          background: linear-gradient(90deg, var(--alico-gold), var(--alico-gold-80));
          border-radius: 10px;
          transition: width 1s ease;
        "></div>
      </div>
      
      <p style="
        font-size: 13px;
        color: #999;
        margin-top: 20px;
      ">
        Esto puede tomar entre 20-40 segundos
      </p>
    </div>
  `;

  document.body.appendChild(overlay);

  // Rotar mensajes cada 6 segundos
  const messageInterval = setInterval(() => {
    currentMessageIndex = (currentMessageIndex + 1) % messages.length;
    const messageEl = document.getElementById('rotatingMessage');
    if (messageEl) {
      messageEl.style.opacity = '0';
      setTimeout(() => {
        messageEl.textContent = messages[currentMessageIndex];
        messageEl.style.opacity = '1';
      }, 300);
    }
  }, 6000);

  // Avanzar barra de progreso gradualmente
  const progressInterval = setInterval(() => {
    const progressBar = document.getElementById('generatingProgressBar');
    if (progressBar && progress < 95) {
      progress += 5;
      progressBar.style.width = progress + '%';
    }
  }, 2000);

  // Retornar función para ocultar el overlay
  return function hideGeneratingOverlay() {
    clearInterval(messageInterval);
    clearInterval(progressInterval);
    const overlayElement = document.getElementById('generatingOverlay');
    if (overlayElement) {
      overlayElement.style.animation = 'fadeOut 0.3s ease-out';
      setTimeout(() => overlayElement.remove(), 300);
    }
  };
}

/**
 * Sistema de Tutorial Interactivo
 * Tutorial paso a paso con spotlight en elementos del dashboard
 */
function startTutorial() {
  // Definir pasos del tutorial
  const tutorialSteps = [
    {
      title: '👋 ¡Bienvenido!',
      description: 'Te mostraremos las funciones principales de tu dashboard en pocos pasos. Puedes salir en cualquier momento.',
      selector: null, // Sin spotlight, solo mensaje central
      action: 'closeSidebar'
    },
    {
      title: '💳 Tus Créditos',
      description: 'Aquí ves tus créditos disponibles. Cada mes recibes 3 créditos nuevos para generar diseños con IA.',
      selector: '.mobile-menu-credits',
      action: 'openSidebar'
    },
    {
      title: '📸 Subir Fotos',
      description: 'Haz clic aquí para subir fotos de tus productos desde tu computadora. Puedes subir hasta 4 fotos.',
      selector: '.action-buttons button:first-child',
      action: 'closeSidebar'
    },
    {
      title: '📱 Subir desde Celular',
      description: 'Genera un código QR para subir fotos directamente desde tu teléfono móvil.',
      selector: '.action-buttons button:nth-child(2)',
      action: null
    },
    {
      title: '📁 Organizar en Carpetas',
      description: 'Crea carpetas para mantener organizadas las fotos de diferentes productos.',
      selector: '.action-buttons button:nth-child(3)',
      action: 'closeSidebar'
    },
    {
      title: '🎨 Generar Diseños con IA',
      description: '¡Esta es la función principal! Aquí creas diseños profesionales de empaques usando Inteligencia Artificial.',
      selector: '.mobile-menu-buttons button[onclick*="forms.html"]',
      action: 'openSidebar'
    },
    {
      title: '📊 Historial de Diseños',
      description: 'Revisa todos tus diseños anteriores y descarga los que necesites.',
      selector: '.mobile-menu-buttons button[onclick*="history.html"]',
      action: 'openSidebar'
    },
    {
      title: '🎉 ¡Todo Listo!',
      description: 'Ya conoces las funciones principales. ¡Comienza subiendo fotos de tus productos y genera tu primer diseño!',
      selector: null,
      action: 'closeSidebar'
    }
  ];

  let currentStep = 0;
  let tutorialOverlay = null;
  let currentHighlightedElement = null;

  // Función para abrir/cerrar sidebar
  function toggleSidebar(open) {
    const mobileMenu = document.getElementById('mobileMenu');
    const mobileMenuOverlay = document.getElementById('mobileMenuOverlay');
    
    if (mobileMenu && mobileMenuOverlay) {
      if (open) {
        mobileMenu.classList.add('active');
        mobileMenuOverlay.classList.add('active');
        // Durante el tutorial, usar z-index alto para sidebar y bloquear interacción
        mobileMenu.style.setProperty('z-index', '2147483646', 'important');
        mobileMenu.style.setProperty('pointer-events', 'none', 'important');
        mobileMenu.style.setProperty('transform', 'translateZ(0)', 'important');
        // Ocultar el overlay oscuro del sidebar (no lo necesitamos, usamos el del tutorial)
        mobileMenuOverlay.style.display = 'none';
      } else {
        mobileMenu.classList.remove('active');
        mobileMenuOverlay.classList.remove('active');
        // Restaurar estilos originales
        mobileMenu.style.removeProperty('z-index');
        mobileMenu.style.removeProperty('pointer-events');
        mobileMenu.style.removeProperty('transform');
        mobileMenuOverlay.style.display = '';
      }
    }
  }

  // Función para resaltar elemento
  function highlightElement(selector, isSidebarOpen) {
    // Limpiar highlight anterior
    if (currentHighlightedElement) {
      currentHighlightedElement.style.position = '';
      currentHighlightedElement.style.removeProperty('position');
      currentHighlightedElement.style.removeProperty('z-index');
      currentHighlightedElement.style.removeProperty('pointer-events');
      currentHighlightedElement.style.removeProperty('box-shadow');
      currentHighlightedElement.style.removeProperty('outline');
      currentHighlightedElement.style.removeProperty('border-radius');
      currentHighlightedElement.style.removeProperty('transform');
      currentHighlightedElement.style.removeProperty('background');
      currentHighlightedElement.style.removeProperty('background-image');
      currentHighlightedElement.style.removeProperty('color');
      // Limpiar estilos de hijos
      const allChildren = currentHighlightedElement.querySelectorAll('*');
      allChildren.forEach(child => {
        child.style.removeProperty('color');
        child.style.removeProperty('fill');
      });
    }

    // Remover overlay oscuro del sidebar anterior
    const oldSidebarOverlay = document.getElementById('tutorialSidebarOverlay');
    if (oldSidebarOverlay) oldSidebarOverlay.remove();

    if (!selector) return;

    const element = document.querySelector(selector);
    if (!element) return;

    // Usar el parámetro para saber si estamos en sidebar
    const isInSidebar = isSidebarOpen;
    
    // Si está en el sidebar, crear overlay oscuro sobre él
    if (isInSidebar) {
      const mobileMenu = document.getElementById('mobileMenu');
      if (mobileMenu) {
        const sidebarOverlay = document.createElement('div');
        sidebarOverlay.id = 'tutorialSidebarOverlay';
        sidebarOverlay.style.cssText = `
          position: absolute !important;
          top: 0 !important;
          left: 0 !important;
          width: 100% !important;
          height: 100% !important;
          background: rgba(0, 0, 0, 0.50) !important;
          z-index: 1 !important;
          pointer-events: none !important;
        `;
        mobileMenu.appendChild(sidebarOverlay);
      }
    }
    
    // Hacer elemento visible sobre el overlay con !important para sobrescribir CSS
    element.style.setProperty('position', 'relative', 'important');
    element.style.setProperty('pointer-events', 'none', 'important');
    
    // Agregar borde dorado brillante y background claro solo para sidebar
    if (isInSidebar) {
      element.style.setProperty('z-index', '10', 'important');
      element.style.setProperty('background', '#ffffff', 'important');
      element.style.setProperty('background-image', 'linear-gradient(135deg, #ffffff 0%, #ffffff 100%)', 'important');
      element.style.setProperty('color', '#000000', 'important');
      element.style.setProperty('filter', 'brightness(1.5) contrast(1.2)', 'important');
      element.style.setProperty('box-shadow', '0 0 0 6px rgba(219, 149, 0, 1), 0 0 50px 20px rgba(255, 215, 0, 1), inset 0 0 30px rgba(255, 255, 255, 0.8)', 'important');
      // Asegurar que los iconos/SVG dentro también sean visibles
      const allChildren = element.querySelectorAll('*');
      allChildren.forEach(child => {
        child.style.setProperty('color', '#000000', 'important');
        child.style.setProperty('fill', '#000000', 'important');
      });
    } else {
      // Elementos fuera del sidebar necesitan z-index altísimo
      element.style.setProperty('z-index', '2147483647', 'important');
      element.style.setProperty('transform', 'translateZ(1px)', 'important');
      element.style.setProperty('box-shadow', '0 0 0 5px rgba(219, 149, 0, 1), 0 0 40px 15px rgba(219, 149, 0, 0.8), inset 0 0 20px rgba(255, 255, 255, 0.3)', 'important');
    }
    element.style.setProperty('outline', '4px solid var(--alico-gold)', 'important');
    element.style.setProperty('border-radius', '12px', 'important');
    
    currentHighlightedElement = element;

    // Scroll suave al elemento si está fuera de vista
    setTimeout(() => {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);
  }

  // Función para mostrar paso actual
  function showStep(stepIndex) {
    const step = tutorialSteps[stepIndex];
    
    // Ejecutar acción del paso (abrir/cerrar sidebar)
    let needsDelay = false;
    if (step.action === 'openSidebar') {
      toggleSidebar(true);
      needsDelay = true;
    } else if (step.action === 'closeSidebar') {
      toggleSidebar(false);
      needsDelay = true;
    }

    // Esperar un poco si hay animación de sidebar
    setTimeout(() => {
      highlightElement(step.selector, step.action === 'openSidebar');
      updateTooltip(step, stepIndex);
    }, needsDelay ? 300 : 0);
  }

  // Función para actualizar tooltip
  function updateTooltip(step, stepIndex) {
    const tooltip = document.getElementById('tutorialTooltip');
    const isFirstStep = stepIndex === 0;
    const isLastStep = stepIndex === tutorialSteps.length - 1;

    tooltip.innerHTML = `
      <button id="tutorialClose" style="
        position: absolute;
        top: 15px;
        right: 15px;
        width: 32px;
        height: 32px;
        border: none;
        background: #f0f0f0;
        color: #666;
        font-size: 24px;
        border-radius: 50%;
        cursor: pointer;
        transition: all 0.2s;
        display: flex;
        align-items: center;
        justify-content: center;
        line-height: 1;
        z-index: 10;
      ">×</button>
      <div style="margin-bottom: 20px;">
        <div style="font-size: 24px; font-weight: 700; color: #1a1a2e; margin-bottom: 12px;">
          ${step.title}
        </div>
        <div style="font-size: 15px; color: #555; line-height: 1.6;">
          ${step.description}
        </div>
        <div style="font-size: 13px; color: #999; margin-top: 12px;">
          Paso ${stepIndex + 1} de ${tutorialSteps.length}
        </div>
      </div>
      <div style="display: flex; gap: 12px; justify-content: space-between;">
        <button id="tutorialPrev" style="
          padding: 10px 20px;
          border: none;
          background: rgba(255, 255, 255, 0.2);
          color: white;
          border-radius: 8px;
          cursor: pointer;
          font-weight: 600;
          font-size: 14px;
          transition: all 0.2s;
          border: 1px solid rgba(255, 255, 255, 0.3);
          ${isFirstStep ? 'visibility: hidden;' : ''}
        ">← Anterior</button>
        <button id="tutorialNext" style="
          padding: 10px 20px;
          border: none;
          background: linear-gradient(135deg, var(--alico-gold) 0%, var(--alico-gold-80) 100%);
          color: white;
          border-radius: 8px;
          cursor: pointer;
          font-weight: 600;
          font-size: 14px;
          transition: all 0.2s;
        ">${isLastStep ? '✓ Finalizar' : 'Siguiente →'}</button>
      </div>
    `;

    // Posicionar tooltip
    positionTooltip(step.selector);

    // Event listeners
    const closeBtn = document.getElementById('tutorialClose');
    const prevBtn = document.getElementById('tutorialPrev');
    const nextBtn = document.getElementById('tutorialNext');

    if (closeBtn) {
      closeBtn.onclick = () => endTutorial(false);
      closeBtn.onmouseover = () => {
        closeBtn.style.background = '#e0e0e0';
        closeBtn.style.transform = 'scale(1.1)';
      };
      closeBtn.onmouseout = () => {
        closeBtn.style.background = '#f0f0f0';
        closeBtn.style.transform = 'scale(1)';
      };
    }

    if (prevBtn) {
      prevBtn.onclick = () => {
        if (currentStep > 0) {
          currentStep--;
          showStep(currentStep);
        }
      };
    }

    if (nextBtn) {
      nextBtn.onclick = () => {
        if (currentStep < tutorialSteps.length - 1) {
          currentStep++;
          showStep(currentStep);
        } else {
          endTutorial(true);
        }
      };
    }
  }

  // Función para posicionar tooltip
  function positionTooltip(selector) {
    const tooltip = document.getElementById('tutorialTooltip');
    
    if (!selector) {
      // Centrar tooltip si no hay elemento resaltado
      tooltip.style.position = 'fixed';
      tooltip.style.top = '50%';
      tooltip.style.left = '50%';
      tooltip.style.transform = 'translate(-50%, -50%)';
      tooltip.style.maxWidth = '450px';
      tooltip.style.width = 'calc(100% - 40px)';
      tooltip.style.bottom = 'auto';
      return;
    }

    const element = document.querySelector(selector);
    if (!element) {
      // Si no encuentra el elemento, centrar el tooltip
      tooltip.style.position = 'fixed';
      tooltip.style.top = '50%';
      tooltip.style.left = '50%';
      tooltip.style.transform = 'translate(-50%, -50%)';
      tooltip.style.maxWidth = '450px';
      tooltip.style.width = 'calc(100% - 40px)';
      tooltip.style.bottom = 'auto';
      return;
    }

    const rect = element.getBoundingClientRect();
    const isInSidebar = element.closest('.mobile-menu') || element.closest('#mobileMenu');
    
    // En móvil o si está en sidebar, centrar abajo
    if (window.innerWidth < 768 || isInSidebar) {
      tooltip.style.position = 'fixed';
      tooltip.style.left = '50%';
      tooltip.style.transform = 'translateX(-50%)';
      tooltip.style.maxWidth = '450px';
      tooltip.style.width = 'calc(100% - 40px)';
      tooltip.style.bottom = '20px';
      tooltip.style.top = 'auto';
      return;
    }

    // Desktop: posicionar cerca del elemento
    const tooltipWidth = 400;
    const gap = 20;

    let top = rect.bottom + gap;
    let left = rect.left;

    // Si no cabe abajo, poner arriba
    if (top + 200 > window.innerHeight) {
      top = rect.top - 200 - gap;
    }

    // Ajustar horizontalmente si se sale de la pantalla
    if (left + tooltipWidth > window.innerWidth) {
      left = window.innerWidth - tooltipWidth - 20;
    }
    if (left < 20) {
      left = 20;
    }

    tooltip.style.position = 'fixed';
    tooltip.style.top = Math.max(20, top) + 'px';
    tooltip.style.left = left + 'px';
    tooltip.style.maxWidth = tooltipWidth + 'px';
    tooltip.style.width = 'auto';
    tooltip.style.transform = 'none';
    tooltip.style.bottom = 'auto';
  }

  // Función para finalizar tutorial
  function endTutorial(completed) {
    // Guardar en localStorage
    if (completed) {
      localStorage.setItem('tutorialCompleted', 'true');
    }

    // Limpiar highlight
    if (currentHighlightedElement) {
      currentHighlightedElement.style.position = '';
      currentHighlightedElement.style.removeProperty('position');
      currentHighlightedElement.style.removeProperty('z-index');
      currentHighlightedElement.style.removeProperty('pointer-events');
      currentHighlightedElement.style.removeProperty('box-shadow');
      currentHighlightedElement.style.removeProperty('outline');
      currentHighlightedElement.style.removeProperty('border-radius');
      currentHighlightedElement.style.removeProperty('transform');
      currentHighlightedElement.style.removeProperty('background');
      currentHighlightedElement.style.removeProperty('background-image');
      currentHighlightedElement.style.removeProperty('color');
      // Limpiar estilos de hijos
      const allChildren = currentHighlightedElement.querySelectorAll('*');
      allChildren.forEach(child => {
        child.style.removeProperty('color');
        child.style.removeProperty('fill');
      });
    }
    
    // Remover overlay oscuro del sidebar
    const sidebarOverlay = document.getElementById('tutorialSidebarOverlay');
    if (sidebarOverlay) sidebarOverlay.remove();

    // Cerrar sidebar si está abierto
    toggleSidebar(false);

    // Restaurar estilos del sidebar
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileMenu) {
      mobileMenu.style.removeProperty('z-index');
      mobileMenu.style.removeProperty('pointer-events');
      mobileMenu.style.removeProperty('transform');
    }

    // Remover overlay
    if (tutorialOverlay) {
      tutorialOverlay.style.animation = 'fadeOut 0.3s ease-out';
      setTimeout(() => {
        tutorialOverlay.remove();
        // Recargar página para restaurar todos los estilos
        if (completed) {
          showNotification('🎉 ¡Tutorial completado! Ya puedes comenzar a usar tu dashboard.', NotificationType.SUCCESS, 2000);
        }
        setTimeout(() => {
          location.reload();
        }, completed ? 2000 : 300);
      }, 300);
    }
  }

  // Crear overlay oscuro
  tutorialOverlay = document.createElement('div');
  tutorialOverlay.id = 'tutorialOverlay';
  tutorialOverlay.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100% !important;
    height: 100% !important;
    background: rgba(0, 0, 0, 0.50) !important;
    z-index: 2147483646 !important;
    pointer-events: none !important;
    animation: fadeIn 0.3s ease-out;
    transform: translateZ(0) !important;
  `;

  // Crear tooltip
  const tooltip = document.createElement('div');
  tooltip.id = 'tutorialTooltip';
  tooltip.style.cssText = `
    position: fixed !important;
    background: white !important;
    padding: 50px 30px 30px 30px !important;
    border-radius: 16px !important;
    box-shadow: 0 10px 50px rgba(0,0,0,0.5) !important;
    z-index: 2147483647 !important;
    pointer-events: auto !important;
    animation: scaleIn 0.3s ease-out;
    transform: translateZ(0) !important;
  `;

  tutorialOverlay.appendChild(tooltip);
  document.body.appendChild(tutorialOverlay);

  // Iniciar tutorial
  showStep(0);

  // Reposicionar tooltip al redimensionar ventana
  window.addEventListener('resize', () => {
    if (currentStep < tutorialSteps.length) {
      positionTooltip(tutorialSteps[currentStep].selector);
    }
  });
}

// Exportar funciones para uso global
window.showNotification = showNotification;
window.showConfirmDialog = showConfirmDialog;
window.showLoader = showLoader;
window.showGeneratingOverlay = showGeneratingOverlay;
window.startTutorial = startTutorial;
window.NotificationType = NotificationType;
