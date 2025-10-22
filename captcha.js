// captcha.js
class HiddenRecaptcha {
    constructor(siteKey) {
        this.siteKey = siteKey;
        this.token = null;
        this.isLoaded = false;
    }

    init() {
        return new Promise((resolve, reject) => {
            // Загружаем reCAPTCHA API
            const script = document.createElement('script');
            script.src = `https://www.google.com/recaptcha/api.js?render=${this.siteKey}`;
            script.async = true;
            script.defer = true;
            
            script.onload = () => {
                this.isLoaded = true;
                console.log('reCAPTCHA loaded');
                this.getToken().then(resolve).catch(reject);
            };
            
            script.onerror = reject;
            document.head.appendChild(script);
        });
    }

    async getToken() {
        if (!this.isLoaded) {
            await this.init();
        }

        return new Promise((resolve, reject) => {
            grecaptcha.ready(async () => {
                try {
                    const token = await grecaptcha.execute(this.siteKey, {
                        action: 'submit'
                    });
                    this.token = token;
                    resolve(token);
                } catch (error) {
                    reject(error);
                }
            });
        });
    }

    // Авто-обновление токена каждые 2 минуты
    startAutoRefresh() {
        setInterval(async () => {
            try {
                this.token = await this.getToken();
                console.log('Token refreshed');
            } catch (error) {
                console.error('Token refresh failed:', error);
            }
        }, 115000); // 1:55 минуты (токен живет 2 минуты)
    }
}

// Создаем глобальный экземпляр
const hiddenCaptcha = new HiddenRecaptcha('6LcdnvMrAAAAAFtHvaUDHAhAEeEtB1EBubhytj');
window.hiddenCaptcha = hiddenCaptcha; // 👈 чтобы main.js видел объект
