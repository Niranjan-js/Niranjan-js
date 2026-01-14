// ===== Notification System =====
class NotificationSystem {
    constructor() {
        this.container = null;
        this.soundEnabled = true;
        this.init();
    }

    init() {
        // Create notification container
        this.container = document.createElement('div');
        this.container.id = 'notificationContainer';
        this.container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            max-width: 400px;
        `;
        document.body.appendChild(this.container);
    }

    show(message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;

        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️',
            critical: '🚨'
        };

        notification.innerHTML = `
            <div style="
                background: ${this.getBackgroundColor(type)};
                border-left: 4px solid ${this.getBorderColor(type)};
                padding: 16px 20px;
                margin-bottom: 12px;
                border-radius: 12px;
                box-shadow: 0 8px 24px rgba(0,0,0,0.3);
                display: flex;
                align-items: center;
                gap: 12px;
                animation: slideIn 0.3s ease-out;
                backdrop-filter: blur(10px);
            ">
                <span style="font-size: 24px;">${icons[type] || icons.info}</span>
                <div style="flex: 1;">
                    <div style="font-weight: 700; margin-bottom: 4px; color: #fff;">${this.getTitle(type)}</div>
                    <div style="font-size: 14px; color: rgba(255,255,255,0.9);">${message}</div>
                </div>
                <button onclick="this.parentElement.parentElement.remove()" style="
                    background: transparent;
                    border: none;
                    color: rgba(255,255,255,0.7);
                    font-size: 20px;
                    cursor: pointer;
                    padding: 0;
                    width: 24px;
                    height: 24px;
                ">×</button>
            </div>
        `;

        this.container.appendChild(notification);

        // Play sound for critical notifications
        if (type === 'critical' && this.soundEnabled) {
            this.playAlertSound();
        }

        // Auto remove
        if (duration > 0) {
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease-out';
                setTimeout(() => notification.remove(), 300);
            }, duration);
        }

        return notification;
    }

    getBackgroundColor(type) {
        const colors = {
            success: 'rgba(34, 197, 94, 0.2)',
            error: 'rgba(239, 68, 68, 0.2)',
            warning: 'rgba(245, 158, 11, 0.2)',
            info: 'rgba(25, 241, 255, 0.2)',
            critical: 'rgba(239, 68, 68, 0.3)'
        };
        return colors[type] || colors.info;
    }

    getBorderColor(type) {
        const colors = {
            success: '#22c55e',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#19f1ff',
            critical: '#ef4444'
        };
        return colors[type] || colors.info;
    }

    getTitle(type) {
        const titles = {
            success: 'Success',
            error: 'Error',
            warning: 'Warning',
            info: 'Information',
            critical: 'CRITICAL ALERT'
        };
        return titles[type] || 'Notification';
    }

    playAlertSound() {
        // Create a simple beep sound using Web Audio API
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();

            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.frequency.value = 800;
            oscillator.type = 'sine';

            gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);

            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.5);
        } catch (e) {
            console.warn('Could not play alert sound:', e);
        }
    }

    toggleSound() {
        this.soundEnabled = !this.soundEnabled;
        return this.soundEnabled;
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Global notification instance
const notifications = new NotificationSystem();
