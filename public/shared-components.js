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
    z-index: 10001;
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

// Exportar funciones para uso global
window.showNotification = showNotification;
window.showConfirmDialog = showConfirmDialog;
window.showLoader = showLoader;
window.showGeneratingOverlay = showGeneratingOverlay;
window.NotificationType = NotificationType;
