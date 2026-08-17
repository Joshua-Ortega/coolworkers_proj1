/*
  Motor Driver Test - XIAO ESP32-C3
  ---------------------------------
  Standalone test for the vibration motor + NPN transistor circuit.
  No BLE, no WiFi, no sleep. Just drives the motor so you can confirm
  the driver stage works before testing the full detector.

  WHAT IT DOES
    1. Full-power pulse (3x) - is the motor alive at all?
    2. Slow ramp up 0 -> 255 - find the duty where it starts spinning
    3. Slow ramp down 255 -> 0
    4. Steps through fixed levels (64/128/192/255), holding each
    Repeats forever. Serial prints the current duty at 115200.

  BOARD SETTINGS
    Tools -> Board: XIAO_ESP32C3
    Tools -> USB CDC On Boot: Enabled
    Do NOT hold BOOT when plugging in.

  WIRING BEING TESTED
    D2 (GPIO4) --[1k]--> NPN base
    NPN emitter -------> GND
    NPN collector -----> motor (-)
    motor (+) ---------> 3V3
    flyback diode across motor, BLACK RING (cathode) to the 3V3 / motor(+) side
*/

const int MOTOR_PIN = 4;    // D2

const int MOTOR_PWM_FREQ = 20000;  // 20 kHz, above hearing
const int MOTOR_PWM_RES  = 8;      // 8-bit: duty 0-255

void setMotor(int duty) {
  if (duty < 0) duty = 0;
  if (duty > 255) duty = 255;
  ledcWrite(MOTOR_PIN, duty);
}

void setup() {
  Serial.begin(115200);
  delay(2000);                     // let USB CDC come up

  ledcAttach(MOTOR_PIN, MOTOR_PWM_FREQ, MOTOR_PWM_RES);
  setMotor(0);

  Serial.println();
  Serial.println("=== Motor driver test ===");
  Serial.println("Motor should be OFF right now.");
  Serial.println("If it is already buzzing, STOP - transistor is stuck on.");
  Serial.println("(base shorted to 3V3, or emitter/collector swapped)");
  delay(3000);
}

void loop() {
  // ---- 1. Full-power pulses: is it alive? ----
  Serial.println("\n[1] Full power pulses x3");
  for (int i = 0; i < 3; i++) {
    setMotor(255);
    Serial.println("    ON  (duty 255)");
    delay(600);
    setMotor(0);
    Serial.println("    off (duty 0)");
    delay(600);
  }

  // ---- 2. Ramp up: find the start-spinning threshold ----
  Serial.println("\n[2] Ramping UP 0 -> 255");
  Serial.println("    Note the duty where it FIRST starts moving:");
  for (int d = 0; d <= 255; d += 5) {
    setMotor(d);
    Serial.printf("    duty %d\n", d);
    delay(120);
  }

  // ---- 3. Ramp down ----
  Serial.println("\n[3] Ramping DOWN 255 -> 0");
  for (int d = 255; d >= 0; d -= 5) {
    setMotor(d);
    delay(80);
  }
  setMotor(0);
  delay(800);

  // ---- 4. Discrete levels (what the detector actually uses) ----
  Serial.println("\n[4] Stepping fixed levels");
  int levels[] = {64, 128, 192, 255};
  for (int i = 0; i < 4; i++) {
    setMotor(levels[i]);
    Serial.printf("    duty %d  (~%d%%)\n", levels[i], (levels[i] * 100) / 255);
    delay(1500);
  }
  setMotor(0);

  Serial.println("\n--- cycle complete, repeating in 3s ---");
  delay(3000);
}
