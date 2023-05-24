/*
Имя пользователя и его пароль передаются в открытом виде в GET параметрах u и p соответственно.
Возможен вариант передачи не пароля, а его хэша.
*/
package url

import (
	"fmt"
	"net/http"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
	"github.com/alrusov/stdhttp"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// Описание
	AuthHandler struct {
		http    *stdhttp.HTTP
		authCfg *config.Auth       // Полная конфигурация аутентификации и авторизации
		cfg     *config.AuthMethod // Стандартная конфигурация этого метода
		options *methodOptions     // Дополнительные параметры конфигурации
	}

	// Дополнительные параметры конфигурации
	methodOptions struct {
		HashedPassword bool `toml:"hashed-password"` // Пароль передается в хешированном виде
	}
)

const (
	module = "url"
	method = "url"
)

//----------------------------------------------------------------------------------------------------------------------------//

// Автоматическая регистрация при запуске приложения
func init() {
	config.AddAuthMethod(module, &methodOptions{})
}

// Проверка валидности дополнительных опций метода
func (options *methodOptions) Check(cfg any) (err error) {
	msgs := misc.NewMessages()

	err = msgs.Error()
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Инициализация метода
func (ah *AuthHandler) Init(cfg *config.Listener) (err error) {
	ah.authCfg = nil
	ah.cfg = nil
	ah.options = nil

	methodCfg, exists := cfg.Auth.Methods[module]
	if !exists || !methodCfg.Enabled || methodCfg.Options == nil {
		return nil
	}

	options, ok := methodCfg.Options.(*methodOptions)
	if !ok {
		return fmt.Errorf(`options for module "%s" is "%T", expected "%T"`, module, methodCfg.Options, options)
	}

	ah.authCfg = &cfg.Auth
	ah.cfg = methodCfg
	ah.options = options
	return nil
}

//----------------------------------------------------------------------------------------------------------------------------//

// Добавить метод листенеру
func Add(http *stdhttp.HTTP) (err error) {
	return http.AddAuthHandler(
		&AuthHandler{
			http: http,
		},
	)
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - метод разрешен?
func (ah *AuthHandler) Enabled() bool {
	return ah.cfg != nil && ah.cfg.Enabled
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - получение индекса для упорядочивания в последовательности вызовов методов
func (ah *AuthHandler) Score() int {
	return ah.cfg.Score
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - получение имени метода и необходимости добавления realm в HTTP заголовок
func (ah *AuthHandler) WWWAuthHeader() (name string, withRealm bool) {
	return method, true
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - попытка аутентификации данным методом
func (ah *AuthHandler) Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (identity *auth.Identity, tryNext bool, err error) {
	queryParams := r.URL.Query()

	u := queryParams.Get("u")
	if u == "" {
		// GET параметр u отсутствует, надо проверять следующим по списку методом
		return nil, true, nil
	}

	p := queryParams.Get("p")

	identity, _, err = auth.StdCheckUser(u, p, ah.options.HashedPassword)
	if err != nil {
		auth.Log.Message(log.INFO, `[%d] URL login error: %s`, id, err)
		return nil, false, err
	}

	if identity == nil {
		auth.Log.Message(log.INFO, `[%d] URL login error: user "%s" not found or illegal password`, id, u)
		return nil, false, fmt.Errorf(`user "%s" not found or illegal password`, u)
	}

	identity.Method = module
	return identity, false, nil
}

//----------------------------------------------------------------------------------------------------------------------------//
