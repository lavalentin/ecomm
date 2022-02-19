package ecomm

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"hash"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/netutil"
)

type DateTimeNowStruct struct {
	Year      int
	YearStr   string
	MonthName string
	Month     int
	MonthStr  string
	Day       int
	DayStr    string
	Hour      int
	HourStr   string
	Minute    int
	MinuteStr string
	Second    int
	SecondStr string
}

type HTTPRequestDataStruct struct {
	//Если удаленный сервер требует SSL аутентификацию -
	//укажите true
	NeedClientSSLAuth bool

	//Если NeedClientSSLAuth=true - укажите имя файла
	//с сертификатом клиента в PEM формате.
	ClientCertFile string

	//Если NeedClientSSLAuth=true - укажите имя файла
	//с ключом клиента в PEM формате.
	ClientKeyFile string

	//Если NeedClientSSLAuth=true - дополнительно можно
	//указать цепочку CA/ROOT сертификатов в PEM формате.
	//Можно оставить пустым
	ListCACertsFile string

	//Таймаут ожидания ответа от сервера в секундах.
	//Если значение не инициализировано (0) - то
	//по умолчанию таймаут будет 30 секунд
	TimeOut int

	//Метод запроса. GET или POST
	Method string

	//URL запроса, например: https://example.com
	URL string

	//Даполнительные заголовки запроса.
	//Можно оставить пустыми.
	//Инициализировать можно так:
	//HTTPRequest.Headers = http.Header{
	//	"Accept-Language": {"en", "ru"},
	//	"Accept":          {"*/*"},
	//}
	//или так:
	//HTTPRequest.Headers = http.Header{}
	//HTTPRequest.Headers.Set("Accept-Language", "en,ru")
	//HTTPRequest.Headers.Set("Accept", "*/*")
	Headers http.Header

	//Заголовок Content-type запроса.
	//Например: application/json
	PostContentType string

	//Если PostContentType НЕ РАВЕН
	//application/x-www-form-urlencoded (сабмит формы <form>),
	//то тело запроса передавать в PostContentBody
	PostContentBody string

	//Если PostContentType РАВЕН
	//application/x-www-form-urlencoded (сабмит формы <form>),
	//то тело запроса передавать в PostFormContentBody.
	//Инициализировать можно так:
	//HTTPRequest.PostFormContentBody = url.Values{
	//	"TERMINAL": {"79036768"},
	//	"DESC":     {"тестовый заказ"},
	//}
	//или так:
	//TTPRequest.PostFormContentBody = url.Values{}
	//HTTPRequest.PostFormContentBody.Add("TERMINAL", "79036768")
	//HTTPRequest.PostFormContentBody.Add("DESC", "тестовый заказ")
	PostFormContentBody url.Values
}

type HTTPResponseDataStruct struct {
	//Код ответа сервера. Например: 200
	StatusCode int

	//Код ответа сервера вместе со строкой. Например: 200 OK
	StatusLine string

	//Заголовки ответа
	Headers http.Header

	//Тело ответа
	Body string

	Error error
}

func (HTTPRequestData *HTTPRequestDataStruct) MakeHTTPRequest() *HTTPResponseDataStruct {
	var HTTPResponseData HTTPResponseDataStruct
	if HTTPRequestData.NeedClientSSLAuth && (HTTPRequestData.ClientCertFile == "" || HTTPRequestData.ClientKeyFile == "") {
		HTTPResponseData.Error = errors.New("no client cert or client key provided, but client ssl auth is true")
		return &HTTPResponseData
	}
	if HTTPRequestData.Method != "GET" && HTTPRequestData.Method != "POST" {
		HTTPResponseData.Error = errors.New("allowed request method is: GET,POST")
		return &HTTPResponseData
	}
	if HTTPRequestData.Method == "POST" && HTTPRequestData.PostContentType == "" {
		HTTPResponseData.Error = errors.New("request PostContentType is null")
		return &HTTPResponseData
	}
	if HTTPRequestData.Method == "POST" && HTTPRequestData.PostContentType == "application/x-www-form-urlencoded" && HTTPRequestData.PostFormContentBody == nil {
		HTTPResponseData.Error = errors.New("request PostFormContentBody is null (expecting PostFormContentBody when content type is application/x-www-form-urlencoded)")
		return &HTTPResponseData
	}
	if HTTPRequestData.Method == "POST" && HTTPRequestData.PostContentType != "application/x-www-form-urlencoded" && HTTPRequestData.PostContentBody == "" {
		HTTPResponseData.Error = errors.New("request PostContentBody is null (expecting PostContentBody when content type is not application/x-www-form-urlencoded)")
		return &HTTPResponseData
	}
	if HTTPRequestData.TimeOut == 0 {
		HTTPRequestData.TimeOut = 30
	}
	if HTTPRequestData.URL == "" {
		HTTPResponseData.Error = errors.New("request URL is null")
		return &HTTPResponseData
	}

	Client := &http.Client{}
	Client.Timeout = time.Duration(HTTPRequestData.TimeOut) * time.Second
	TLSConfig := tls.Config{}
	TLSConfig.InsecureSkipVerify = true

	if HTTPRequestData.NeedClientSSLAuth {
		ClientCert, ClentCertLoadError := tls.LoadX509KeyPair(HTTPRequestData.ClientCertFile, HTTPRequestData.ClientKeyFile)
		if ClentCertLoadError != nil {
			HTTPResponseData.Error = errors.New("client cert and key load error: " + ClentCertLoadError.Error())
			return &HTTPResponseData
		}
		TLSConfig.Certificates = []tls.Certificate{ClientCert}
		if HTTPRequestData.ListCACertsFile != "" {
			ListCACertsContent, ReadListCACertsError := ioutil.ReadFile(HTTPRequestData.ListCACertsFile)
			if ReadListCACertsError != nil {
				HTTPResponseData.Error = errors.New("read ca certs file error: " + ReadListCACertsError.Error())
				return &HTTPResponseData
			}
			ListCACerts := x509.NewCertPool()
			ListCACerts.AppendCertsFromPEM(ListCACertsContent)
			TLSConfig.RootCAs = ListCACerts
		}
	}

	Client.Transport = &http.Transport{TLSClientConfig: &TLSConfig}

	var Request *http.Request
	var RequestError error
	var Response *http.Response
	var ResponseError error
	PostDataBuffer := new(bytes.Buffer)

	if HTTPRequestData.Method == "GET" {
		Request, RequestError = http.NewRequest("GET", HTTPRequestData.URL, nil)
	} else if HTTPRequestData.Method == "POST" && HTTPRequestData.PostContentType == "application/x-www-form-urlencoded" {
		PostDataBuffer.WriteString(HTTPRequestData.PostFormContentBody.Encode())
		Request, RequestError = http.NewRequest("POST", HTTPRequestData.URL, PostDataBuffer)
	} else {
		PostDataBuffer.WriteString(HTTPRequestData.PostContentBody)
		Request, RequestError = http.NewRequest("POST", HTTPRequestData.URL, PostDataBuffer)
	}

	if RequestError != nil {
		HTTPResponseData.Error = errors.New("create request error: " + RequestError.Error())
		return &HTTPResponseData
	}

	if HTTPRequestData.Headers != nil {
		Request.Header = HTTPRequestData.Headers
	}
	Request.Header.Set("Content-Type", HTTPRequestData.PostContentType)

	Response, ResponseError = Client.Do(Request)
	if ResponseError != nil {
		HTTPResponseData.Error = errors.New("get response error: " + ResponseError.Error())
		return &HTTPResponseData
	}

	defer Response.Body.Close()

	ResponseContent, ResponseContentError := ioutil.ReadAll(Response.Body)
	if ResponseContentError != nil {
		HTTPResponseData.Error = errors.New("response read error: " + ResponseContentError.Error())
		return &HTTPResponseData
	}

	HTTPResponseData.StatusCode = Response.StatusCode
	HTTPResponseData.StatusLine = Response.Status
	HTTPResponseData.Headers = Response.Header
	HTTPResponseData.Body = string(ResponseContent)

	return &HTTPResponseData
}

type LogDataStruct struct {
	//Директория куда писать лог
	Dir string

	//Имя файла куда писать лог.
	//Перед именем файла создается
	//префикс с текущей датой если использовать метод Write()
	//если же использовать WriteCycle() префикса с датой не будет
	FileName string

	//Текст который будет написан в логе перед LogData
	DataPrefix string

	//Данные для логирования
	Data interface{}

	//Максимальный размер лога в байтах.
	//Актуально для метода CycleWrite.
	//Метод Write не использует MaxFileSizeInBytes, т.к.размер неограничен
	MaxFileSizeInBytes int
}

func (LogData *LogDataStruct) CheckDir() {
	//если последний символ не / то надо обавить, чтобы при склейке с именем файла путь правильный получился
	if LogData.Dir[len(LogData.Dir)-1:len(LogData.Dir)] != "/" {
		LogData.Dir += "/"
	}
}

//@Lakhtin: использую error в виде строки на выходе чтобы не раздражать линтер. Иначе заставит при любом вызове проверять error. Код распухнет...
func (LogData *LogDataStruct) Write() string {
	LogData.CheckDir()
	Now := DateTimeNow()
	LogFile, OpenErr := os.OpenFile(LogData.Dir+Now.YearStr+Now.MonthStr+Now.DayStr+"_"+LogData.FileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if OpenErr != nil {
		return OpenErr.Error()
	}
	defer LogFile.Close()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(LogFile)
	log.Println(LogData.DataPrefix, LogData.Data)

	return ""
}

//@Lakhtin: использую error в виде строки на выходе чтобы не раздражать линтер. Иначе заставит при любом вызове проверять error. Код распухнет...
func (LogData *LogDataStruct) WriteCycle() string {
	LogData.CheckDir()
	LogFileStat, LogFileStatError := os.Stat(LogData.Dir + LogData.FileName)
	if LogFileStatError != nil {
		return LogFileStatError.Error()
	}
	LogFileCurrentSize := LogFileStat.Size()
	var LogFileOpenRegime int
	if LogFileCurrentSize >= int64(LogData.MaxFileSizeInBytes) {
		LogFileOpenRegime = os.O_TRUNC | os.O_WRONLY
	} else {
		LogFileOpenRegime = os.O_APPEND | os.O_WRONLY
	}
	LogFile, OpenErr := os.OpenFile(LogData.Dir+LogData.FileName, LogFileOpenRegime, 0644)
	if OpenErr != nil {
		return OpenErr.Error()
	}
	defer LogFile.Close()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(LogFile)
	log.Println(LogData.MaxFileSizeInBytes, LogData)

	return ""
}

type PSignDataStruct struct {
	//Структура с полями для получения строки MacData
	//ВАЖНО соблюдать последовательность полей
	//при создании структуры
	MacData interface{}

	//Сформированная строка MacData для подписи
	MacDataFormed string

	//HEX ключ
	KeyHex string

	//Алгортим формирования подписи
	Alg string

	//Подпись которую необходимо проверить.
	PSignToBeChecked string

	//Рассчитанная Подпись
	PSignCalculated string
}

func (PSignData *PSignDataStruct) ToMacData(Str string) string {
	if len(Str) == 0 {
		return "-"
	} else {
		return strconv.Itoa(len(Str)) + Str
	}
}

func (PSignData *PSignDataStruct) CalcPSignHex() error {
	type PSignInterface interface{ hash.Hash }
	var PSign PSignInterface
	KeyBin, KeyErr := hex.DecodeString(PSignData.KeyHex)
	if KeyErr != nil {
		return errors.New("key convertation from hex to bin error")
	}
	if strings.ToUpper(PSignData.Alg) == "SHA256" {
		PSign = hmac.New(sha256.New, KeyBin)
	} else {
		PSign = hmac.New(sha1.New, KeyBin)
	}
	PSign.Write([]byte(PSignData.MacDataFormed))
	PSignData.PSignCalculated = hex.EncodeToString(PSign.Sum(nil))
	return nil
}

func (PSignData *PSignDataStruct) CheckPSign() (bool, error) {
	MacDataType := reflect.TypeOf(PSignData.MacData)
	if MacDataType.Kind().String() != "struct" {
		return false, errors.New("CheckPSign: MacData must be struct")
	}

	for i := 0; i < MacDataType.NumField(); i++ {
		if MacDataType.Field(i).Type.String() != "string" {
			return false, errors.New("CheckPSign: MacData struct must contain only strings value")
		}
		FieldValue := reflect.ValueOf(PSignData.MacData).Field(i).String()
		PSignData.MacDataFormed = PSignData.MacDataFormed + PSignData.ToMacData(FieldValue)
	}
	CalcPSignHexError := PSignData.CalcPSignHex()
	if CalcPSignHexError != nil {
		return false, CalcPSignHexError
	}
	if strings.EqualFold(PSignData.PSignToBeChecked, PSignData.PSignCalculated) {
		return true, nil
	}

	return true, nil
}

//PaddingDirection может быть L (строка будет дополнена слева)
//или R (строка будет дополнена справа)
func FixStrLen(Str, PaddingDirection, PaddingSymbol string, OutLen int) string {
	StrLen := len(Str)
	if StrLen >= OutLen {
		return Str[0:OutLen]
	}
	PaddingCount := OutLen - StrLen
	for i := 1; i <= PaddingCount; i++ {
		if PaddingDirection == "L" {
			Str = PaddingSymbol + Str
		} else if PaddingDirection == "R" {
			Str = Str + PaddingSymbol
		} else {
			return ""
		}
	}

	return Str
}

func DateTimeNow() DateTimeNowStruct {
	var DateTimeNow DateTimeNowStruct
	MonthsNumDict := map[string]int{
		"January":   1,
		"February":  2,
		"March":     3,
		"April":     4,
		"May":       5,
		"June":      6,
		"July":      7,
		"August":    8,
		"September": 9,
		"October":   10,
		"November":  11,
		"December":  12,
	}

	Now := time.Now()

	DateTimeNow.Year = Now.Year()
	DateTimeNow.YearStr = strconv.Itoa(DateTimeNow.Year)
	DateTimeNow.MonthName = Now.Month().String()
	DateTimeNow.Month = MonthsNumDict[DateTimeNow.MonthName]
	DateTimeNow.MonthStr = FixStrLen(strconv.Itoa(DateTimeNow.Month), "L", "0", 2)
	DateTimeNow.Day = Now.Day()
	DateTimeNow.DayStr = FixStrLen(strconv.Itoa(DateTimeNow.Day), "L", "0", 2)
	DateTimeNow.Hour = Now.Hour()
	DateTimeNow.HourStr = FixStrLen(strconv.Itoa(DateTimeNow.Hour), "L", "0", 2)
	DateTimeNow.Minute = Now.Minute()
	DateTimeNow.MinuteStr = FixStrLen(strconv.Itoa(DateTimeNow.Minute), "L", "0", 2)
	DateTimeNow.Second = Now.Second()
	DateTimeNow.SecondStr = FixStrLen(strconv.Itoa(DateTimeNow.Second), "L", "0", 2)

	return DateTimeNow
}

func ParseConf(ConfFileName string) (map[string]string, error) {
	ConfFile, OpenError := os.Open(ConfFileName)
	if OpenError != nil {
		return nil, OpenError
	}
	defer ConfFile.Close()

	Conf := make(map[string]string)
	ConfLine := bufio.NewScanner(ConfFile)
	ConfLineIsCommentTemplate, _ := regexp.Compile(`^\s*#`)
	ConfLineTemplate, _ := regexp.Compile(`(.+?)=(.+)`)
	for ConfLine.Scan() {
		if !ConfLineIsCommentTemplate.MatchString(ConfLine.Text()) && ConfLineTemplate.MatchString(ConfLine.Text()) {
			matches := ConfLineTemplate.FindStringSubmatch(ConfLine.Text())
			Conf[matches[1]] = matches[2]
		}
	}

	return Conf, nil
}

//Regime может быть:
//BIGCHARS - это [A-Z].
//BIGCHARSRU - это [А-Я].
//SMALLCHARS - это [a-z].
//SMALLCHARSRU - это [а-я].
//SPECIALS - это спец. символы.
//DIGITS - это цифры.
//Если Regime ни один из вышеперечисленных - вернется пустая строка.
//Максимальная длина строки = 2000 символов.
//Если указать больше - сокращается до 2000
func RndCharsString(Regime string, StringLen int) string {
	CharsBigSet := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	CharsBigRUSet := []rune("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
	CharsSmallSet := []rune("abcdefghijklmnopqrstuvwxyz")
	CharsSmallRUSet := []rune("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")
	CharsSpecialSet := []rune("~!@#$%^&*()_-+=")
	CharsDigitSet := []rune("1234567890")

	switch Regime {
	case "BIGCHARS":
		return RndCharsFromSet(CharsBigSet, StringLen)
	case "BIGCHARSRU":
		return RndCharsFromSet(CharsBigRUSet, StringLen)
	case "SMALLCHARS":
		return RndCharsFromSet(CharsSmallSet, StringLen)
	case "SMALLCHARSRU":
		return RndCharsFromSet(CharsSmallRUSet, StringLen)
	case "SPECIALS":
		return RndCharsFromSet(CharsSpecialSet, StringLen)
	case "DIGITS":
		return RndCharsFromSet(CharsDigitSet, StringLen)
	}

	return ""
}

func RndCharsFromSet(CharsSet []rune, StringLen int) string {
	if len(CharsSet) == 0 {
		return ""
	}
	if StringLen > 2000 {
		StringLen = 2000
	}
	CharsSetLen := len(CharsSet)
	var OutString string
	var RndIndexOfSet int
	//Sleep необходим чтобы гарантировать уникальный Seed
	//в рамках вызова из одной программы
	time.Sleep(time.Nanosecond)
	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))
	for i := 0; i < StringLen; i++ {
		RndIndexOfSet = rand.Intn(CharsSetLen)
		OutString += string(CharsSet[RndIndexOfSet : RndIndexOfSet+1])
	}

	return OutString
}

func GetTCPListener(Port string, MaxConn int) (net.Listener, error) {
	Listener, ListenerError := net.Listen("tcp", ":"+Port)
	if ListenerError != nil {
		return nil, ListenerError
	}
	Listener = netutil.LimitListener(Listener, MaxConn)

	return Listener, nil
}

func GetTCPTransmittedData(Conn net.Conn, ReadTimeOutSecond int) (string, error) {
	Conn.SetReadDeadline(time.Now().Add(time.Duration(ReadTimeOutSecond) * time.Second))
	Scanner := bufio.NewScanner(Conn)
	var Request string
	for Scanner.Scan() {
		Request = Request + Scanner.Text() + "\n"
	}
	if len(Request) == 0 {
		Conn.Close()
		return "", errors.New("request read time out")
	}
	//убираем последний перенос строки который сами сделали
	//в цикле Scanner выше
	Request = Request[:len(Request)-1]
	return Request, nil
}
