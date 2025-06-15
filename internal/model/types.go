package model

import (
	"encoding/xml"
	"time"
)

// Client — клиент, которому назначен тариф
type Client struct {
	ClientID    string `json:"clientId"`
	TariffID    int    `json:"tariffId"`
	ClientType  string `json:"clientType"`
	AccountType string `json:"accountType"`
	UserID      int    `json:"userId"`
}

// Tariff — тарифный план с параметрами расчета
type Tariff struct {
	ID         int
	Name       string
	FixedFee   float64
	PercentFee float64
	MinFee     float64
	MaxFee     float64
	CalcMode   string // "sum", "min", "max"
}

// ThresholdRule - правила расчета пороговых значений тарифов
type ThresholdRule struct {
	ID          int
	TariffID    int
	FromCount   int // С какого количества операций действует
	ToCount     int // До какого количества
	FixedFee    float64
	PercentFee  float64
	MinFee      float64
	MaxFee      float64
	CalcMode    string // "sum", "min", "max"
	MCC         string
	ClientType  string
	AccountType string
	OpType      string
}

// User - пользователь
type User struct {
	ID           int
	Username     string
	PasswordHash string
	Role         string
}

// Operation - список операций пользователя
type Operation struct {
	ID        int
	ClientID  string
	Amount    float64
	CreatedAt time.Time
}

type CalcRequest struct {
	XMLName        xml.Name `xml:"CalcRequest" json:"-"`
	ClientID       string   `xml:"ClientID" json:"clientId"`
	Amount         float64  `xml:"Amount" json:"amount"`
	OperationCount int      `xml:"OperationCount" json:"operationCount"`
	MCC            string   `xml:"MCC" json:"mcc,omitempty"`
	ClientType     string   `xml:"ClientType" json:"clientType,omitempty"`
	AccountType    string   `xml:"AccountType" json:"accountType,omitempty"`
	OperationType  string   `xml:"OperationType" json:"operationType,omitempty"`
}

type CalcResponse struct {
	XMLName        xml.Name `xml:"CalcResponse" json:"-"`
	Product        string   `xml:"Product" json:"product"`
	Commission     float64  `xml:"Commission" json:"commission"`
	OperationCount int      `xml:"OperationCount" json:"operationCount"`
}
