package kafka

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os"

	kafka "github.com/segmentio/kafka-go"
	"tariff-module-backend/internal/db"
	"tariff-module-backend/internal/model"
	"tariff-module-backend/internal/service"
)

// StartXMLConsumer запускает Kafka consumer для обработки XML-запросов на расчет комиссии
func StartXMLConsumer() {
	// Чтение из Kafka
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{os.Getenv("KAFKA_BROKER")},
		Topic:    os.Getenv("KAFKA_TOPIC_XML_REQUEST"),
		GroupID:  "xml-consumer-group",
		MinBytes: 10e3,
		MaxBytes: 10e6,
	})
	defer reader.Close()

	// Отправка в Kafka
	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{os.Getenv("KAFKA_BROKER")},
		Topic:   os.Getenv("KAFKA_TOPIC_XML_RESPONSES"),
	})
	defer writer.Close()

	log.Printf("[Kafka/XML] Старт подписки на топик: %s", os.Getenv("KAFKA_TOPIC_XML_REQUEST"))

	for {
		msg, err := reader.ReadMessage(context.Background())
		if err != nil {
			log.Printf("[Kafka/XML] Ошибка чтения сообщения: %v", err)
			continue
		}

		var req model.CalcRequest
		if err := xml.Unmarshal(msg.Value, &req); err != nil {
			log.Printf("[Kafka/XML] Ошибка парсинга XML: %v", err)
			continue
		}

		tariff, err := db.GetTariffByClientID(req.ClientID)
		if err != nil {
			log.Printf("[Kafka/XML] Тариф не найден: %v", err)
			continue
		}

		resp := service.ProcessKafkaCalculationWithTariff(req, tariff)

		xmlResp, err := xml.Marshal(resp)
		if err != nil {
			log.Printf("[Kafka/XML] Ошибка сериализации XML: %v", err)
			continue
		}

		err = writer.WriteMessages(context.Background(), kafka.Message{
			Key:   []byte(fmt.Sprintf("client-%s", req.ClientID)),
			Value: xmlResp,
		})
		if err != nil {
			log.Printf("[Kafka/XML] Ошибка отправки в Kafka: %v", err)
		}
	}
}
