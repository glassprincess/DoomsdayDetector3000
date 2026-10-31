//! Doomsday генерирует случайные имена классов при каждой сборке, поэтому
//! ловить их по конкретным строкам бессмысленно — вместо этого здесь три
//! структурные эвристики под три наблюдаемых режима генерации имён.

/// Явный мусор: короткий toKEN из строчных букв+цифр без гласных —
/// `v5wx2kx`, `0lv5ybz`, `xnjret42ssse`, `g0ikmd`. Пакет (если есть) не важен,
/// смотрим только на последний сегмент имени.
fn is_blatant(local: &str) -> bool {
    let len = local.chars().count();
    if !(6..=16).contains(&len) {
        return false;
    }
    if !local.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return false;
    }
    if !local.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let vowels = local.chars().filter(|c| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u')).count();
    (vowels as f64) / (len as f64) < 0.30
}

/// Менее очевидный режим: короткий рандомный "пакет" плюс длинный хаотичный
/// локальный токен. У Doomsday есть две формы пакета: `2h73` (строчные буквы +
/// цифры вперемешку) и `cITf` (смешанный регистр). Общий сигнал — пакет НЕ похож
/// на настоящий Java-пакет: короткий токен, который либо содержит цифру, либо
/// имеет смешанный регистр (реальные пакеты `java`, `com`, `net` — всегда
/// строчные и без цифр). Локальный токен — длинный хаотичный alnum с `$`/`_`,
/// цифрами и смешанным регистром, вида `KUOWYickmwqy1$5ACMGOq1eyBiA7Alq`.
/// Дескрипторы массива `[L...;` (в т.ч. вложенные `[[L...;`) снимаем заранее.
fn is_normal(stripped: &str) -> bool {
    let Some(slash) = stripped.rfind('/') else { return false };
    let prefix = &stripped[..slash];
    let local = &stripped[slash + 1..];

    if !(2..=8).contains(&prefix.chars().count()) {
        return false;
    }
    if !prefix.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let has_digit = prefix.chars().any(|c| c.is_ascii_digit());
    let has_upper = prefix.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = prefix.chars().any(|c| c.is_ascii_lowercase());
    // Сигнал "пакет сгенерирован рандомом": цифра вперемешку с буквами (`2h73`)
    // ИЛИ смешанный регистр (`cITf`). Обычные Java-пакеты этим не обладают.
    if !(has_digit || (has_upper && has_lower)) {
        return false;
    }

    if local.chars().count() < 10 {
        return false;
    }
    if !local.chars().all(|c| c.is_ascii_alphanumeric() || c == '$' || c == '_') {
        return false;
    }
    if !local.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    let has_upper = local.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = local.chars().any(|c| c.is_ascii_lowercase());
    has_upper && has_lower
}

/// Маскировка под ванильные обфусцированные имена (2-4 строчные буквы,
/// опционально `$` + одна строчная буква — `bdj$a`, `zxp`, `zws`). Такие имена
/// САМИ ПО СЕБЕ абсолютно нормальны и массово встречаются в любом ванильном
/// дампе — подозрительна не сама форма, а аномальная плотность именно в самом
/// начале дампа, где обычно идут lambda-классы JDK, а не пачка коротких
/// "ванильных" имён. Поэтому это не per-имя, а оконная проверка (см. scan()).
fn looks_vanilla_short(stripped: &str) -> bool {
    if stripped.contains('/') {
        return false;
    }
    let base = match stripped.rfind('$') {
        Some(idx) => {
            let suffix = &stripped[idx + 1..];
            if suffix.chars().count() != 1 || !suffix.chars().all(|c| c.is_ascii_lowercase()) {
                return false;
            }
            &stripped[..idx]
        }
        None => stripped,
    };
    (2..=4).contains(&base.chars().count()) && base.chars().all(|c| c.is_ascii_lowercase())
}

fn strip_array_wrapper(name: &str) -> &str {
    let mut s = name;
    while let Some(rest) = s.strip_prefix('[') {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix('L') {
        if let Some(end) = rest.strip_suffix(';') {
            s = end;
        }
    }
    s
}

/// Doomsday встраивает в имена классов непечатные/не-ASCII байты (контрольные
/// символы), чтобы обойти наивные детекторы, которые требуют чистый ASCII
/// (см. `is_ascii_lowercase`/`is_ascii_digit` ниже — любой такой байт роняет
/// проверку, и класс проходит незамеченным). Здесь мы сбрасываем эти байты
/// перед анализом формы имени: после чистки остаётся читаемый токен вроде
/// `q0/hx2rmnoxos`, по которому эвристики уже срабатывают.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control() && *c != ' ')
        .collect()
}

const VANILLA_WINDOW_CAP: usize = 300;
const VANILLA_ABS_THRESHOLD: usize = 25;
const VANILLA_RATIO_PCT: usize = 20;
const SAMPLE_LIMIT: usize = 10;

pub struct DoomsdayFindings {
    pub blatant: Vec<String>,
    pub normal: Vec<String>,
    pub vanilla_window: usize,
    pub vanilla_total_in_window: usize,
    pub vanilla_sample: Vec<String>,
}

impl DoomsdayFindings {
    pub fn vanilla_flagged(&self) -> bool {
        if self.vanilla_window == 0 {
            return false;
        }
        self.vanilla_total_in_window >= VANILLA_ABS_THRESHOLD
            || self.vanilla_total_in_window * 100 / self.vanilla_window >= VANILLA_RATIO_PCT
    }

    pub fn is_clean(&self) -> bool {
        self.blatant.is_empty() && self.normal.is_empty() && !self.vanilla_flagged()
    }
}

pub fn scan(classes: &[String]) -> DoomsdayFindings {
    let mut blatant = Vec::new();
    let mut normal = Vec::new();

    for name in classes {
        let normalized = normalize(name);
        let stripped = strip_array_wrapper(&normalized);
        let local = stripped.rsplit('/').next().unwrap_or(stripped);
        if is_blatant(local) {
            blatant.push(name.clone());
        } else if is_normal(stripped) {
            normal.push(name.clone());
        }
    }

    let window = (classes.len() / 10).min(VANILLA_WINDOW_CAP);
    let mut vanilla_total = 0usize;
    let mut vanilla_sample = Vec::new();
    for name in classes.iter().take(window) {
        let normalized = normalize(name);
        let stripped = strip_array_wrapper(&normalized);
        if looks_vanilla_short(stripped) {
            vanilla_total += 1;
            if vanilla_sample.len() < SAMPLE_LIMIT {
                vanilla_sample.push(name.clone());
            }
        }
    }

    DoomsdayFindings { blatant, normal, vanilla_window: window, vanilla_total_in_window: vanilla_total, vanilla_sample }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blatant_examples_are_detected() {
        for name in ["pax/v5wx2kx", "0lv5ybz", "xnjret42ssse", "pax/g0ikmd"] {
            let stripped = strip_array_wrapper(name);
            let local = stripped.rsplit('/').next().unwrap();
            assert!(is_blatant(local), "expected blatant hit for {name}");
        }
    }

    #[test]
    fn normal_examples_are_detected_with_and_without_array_wrapper() {
        let examples = [
            "[L2h73/KUOWYickmwqy1$5ACMGOq1eyBiA7Alq;",
            "[L2h73/RGAITICKVKEMXMGOZOIqzedBiA7Ak2;",
            "2h73/RGAITICKVKEMXMGOZOIqzedBiA7Ak2",
            "2h73/peYgTICK0ys1ncWeRGAI8wqylaUqbedBiA7AM2",
            "2h73/VqBedBiA7Ay1",
            "2h73/nqkspqle2BiA7AWt",
            "2h73/IdXfDYSa$TNV6OIQ1JqSeDBiA7ADr$",
            // Вторая форма пакета — смешанный регистр (`cITf`), реальный дамп.
            "cITf/RU9AloqmeKBpALAb_",
            "cITf/4lNR9qSWBvXbG1cgL6hlQ$q3e6BpALAr$",
            "cITf/OR60hqleKBpALAa_",
            // Вложенный дескриптор массива `[[L...;`.
            "[[LcITf/y2dhRU9AwzbfPS7$uqxeKBpALAm_;",
            "[[LcITf/LO37qkeKBpALAZ_;",
        ];
        for name in examples {
            let stripped = strip_array_wrapper(name);
            assert!(is_normal(stripped), "expected normal hit for {name}");
        }
    }

    #[test]
    fn vanilla_short_examples_match_the_shape() {
        for name in ["bdj$a", "bbo$a", "bav$a", "bac$a", "zxp", "zxk", "zxo", "zxv", "zxs", "zwt", "zws", "beb$a", "bea$a", "zxg"] {
            assert!(looks_vanilla_short(name), "expected vanilla-shape hit for {name}");
        }
    }

    #[test]
    fn ordinary_java_names_are_not_flagged() {
        let ordinary = [
            "java/lang/String",
            "java/util/HashMap$Node",
            "net/minecraft/client/Minecraft",
            "kotlin/jvm/internal/Intrinsics",
            "com/example/utils/Base64Encoder",
            "org/apache/commons/lang3/StringUtils",
        ];
        for name in ordinary {
            let stripped = strip_array_wrapper(name);
            let local = stripped.rsplit('/').next().unwrap();
            assert!(!is_blatant(local), "false positive (blatant) for {name}");
            assert!(!is_normal(stripped), "false positive (normal) for {name}");
        }
        // Обычные короткие обфусцированные ProGuard-имена ("a", "b", "c", "aa")
        // сами по себе не должны триггерить: они слишком короткие для vanilla-окна
        // либо не образуют аномальной плотности сами по себе — здесь проверяем
        // только форму отдельного имени, плотность считается на всём окне в scan().
        assert!(!looks_vanilla_short("java/lang/String"));
    }

    #[test]
    fn mojibake_names_with_embedded_control_bytes_are_still_detected() {
        // Реальные имена Doomsday из дампа: в строку вписаны непечатные байты,
        // которые раньше роняли is_ascii_* проверки и детектор их не видел.
        // normalize() должен сбрасывать эти байты и находить форму имени.
        let raw = [
            "q\u{15}\u{1c}0/3\u{1}psk\u{13}i\u{0c}f\u{1a}ua\u{11}j\u{4}4pd3qiwk5un\u{17}",
            "q\u{15}\u{1c}0/hx\u{11}\u{8}2r\u{19}m\u{17}\u{15}n\u{0e}ox\u{7f}\u{0e}\u{7f}os",
            "1wk54cybae",
        ];
        let findings = scan(&raw.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(findings.blatant.len() >= 2, "expected blatant hits, got {:?}", findings.blatant);
    }
}
