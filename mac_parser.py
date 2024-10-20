from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import time

# Настройка Selenium WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))

# Задайте URL сайта, который нужно парсить
url = 'https://macaddress.io/statistics/company/861'
driver.get(url)

try:
    # Явное ожидание: ждем, пока таблица не станет видимой
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "table"))
    )

    # Находим общее количество страниц (пагинация внизу таблицы)
    pagination = driver.find_element(By.CSS_SELECTOR, ".dataTables_paginate")  # Пагинация может иметь другой селектор
    last_page_button = pagination.find_elements(By.CSS_SELECTOR, ".paginate_button")[-2]  # Предпоследний элемент — это последняя страница (обычно кнопка)
    total_pages = int(last_page_button.text)  # Извлекаем номер последней страницы
    print(f"Всего страниц: {total_pages}")

    # Инициализируем список для всех строк таблицы
    all_rows = []

    # Цикл по всем страницам
    for page in range(total_pages):
        # Получение HTML-кода текущей страницы
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')

        # Находим все строки таблицы
        rows = soup.select('tr.odd[role="row"], tr.even[role="row"]')

        # Добавляем строки в общий список
        all_rows.extend(rows)

        # Переход на следующую страницу, если это не последняя
        if page < total_pages - 1:
            next_button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, ".paginate_button.next"))
            )

            # Скроллим до кнопки "Next"
            driver.execute_script("arguments[0].scrollIntoView(true);", next_button)
            time.sleep(1)

            # Выполняем клик с помощью JavaScript
            driver.execute_script("arguments[0].click();", next_button)
            time.sleep(2)  # Ожидание загрузки следующей страницы

    print(f"Всего строк собрано: {len(all_rows)}")

    # Имя файла для записи данных
    filename = 'output.txt'

    # Записываем данные в файл
    if len(all_rows) == 0:
        print("Не удалось найти строки в таблице.")
    else:
        with open(filename, 'w', encoding='utf-8') as file:
            for row in all_rows:
                first_cell = row.find('td')
                if first_cell:
                    file.write(first_cell.text.strip() + '\n')
                    print(f"Записано: {first_cell.text.strip()}")

    print(f"Данные успешно записаны в файл {filename}.")

finally:
    # Закрытие веб-драйвера
    driver.quit()
