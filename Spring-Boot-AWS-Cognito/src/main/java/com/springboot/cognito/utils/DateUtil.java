package com.springboot.cognito.utils;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

public class DateUtil {

	public static String getDate() {

		// Create a TimeZone object for IST
		TimeZone istTimeZone = TimeZone.getTimeZone("Asia/Kolkata");

		// Create a Calendar object and set the IST time zone on it
		Calendar calendar = Calendar.getInstance();
		calendar.setTimeZone(istTimeZone);

		// Get the current date in IST
		Date istDate = calendar.getTime();

		// Create a SimpleDateFormat object for GMT time zone
		SimpleDateFormat gmtFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy");
		gmtFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

		// Format the IST date in GMT format
		return gmtFormat.format(istDate);
	}
	
}