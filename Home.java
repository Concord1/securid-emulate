import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.Color;
import javax.swing.JLabel;
import java.time.*;
import java.util.Date;
import javax.swing.SwingConstants;
import java.awt.Rectangle;
import javax.swing.BoxLayout;
import java.awt.CardLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import java.awt.FlowLayout;
import java.awt.Dimension;
import java.awt.Component;

public class Home extends JFrame {

	private JPanel contentPane;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Home frame = new Home();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		
	}

	/**
	 * Create the frame.
	 */
	public Home() {
		
		
//		
//		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//		setBounds(100, 100, 530, 334);
//		contentPane = new JPanel();
//		contentPane.setBackground(Color.WHITE);
//		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
//		contentPane.setLayout(new BorderLayout(0, 0));
//		setContentPane(contentPane);
//		
		String seed = "4gk6txq2f9c974px";
		
		
		Instant start = Instant.parse("1986-01-01T00:00:00.00Z");
		Instant end = Instant.now();		        
		Duration duration = Duration.between(start, end);
		int sec = (int)(duration.getSeconds());
		int min = (int) Math.floor(sec/60);
		String[] Args = {seed, Integer.toString(min*60)};
		String tok = AES.finalRead(Args);
		getContentPane().setLayout(new BorderLayout(0, 0));
		
		JLabel lblNewLabel = new JLabel(tok);
		lblNewLabel.setHorizontalTextPosition(SwingConstants.CENTER);
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
		lblNewLabel.setMinimumSize(new Dimension(13, 13));
		lblNewLabel.setMaximumSize(new Dimension(13, 13));
		getContentPane().add(lblNewLabel, BorderLayout.CENTER);
		setBounds(100, 100, 530, 334);
		
	}

}
